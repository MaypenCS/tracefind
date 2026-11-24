"""Glue between tracefind's existing scanners and the report/history modules."""
from __future__ import annotations

from datetime import date

from .report.adapters import categorize
from .report.models import Breach, PasteHit, ScanResult, SourceStatus, UsernameHit
from .sites import load_sites

PROVIDER_NAMES = {"xposedornot": "XposedOrNot", "hibp": "HaveIBeenPwned", "dehashed": "Dehashed",
                  "intelx": "IntelX"}

# Dehashed field names (as breach.py reports them, underscores -> spaces) -> readable data classes
_DEHASHED_LABELS = {
    "email": "Email addresses", "username": "Usernames", "name": "Names", "password": "Passwords",
    "hashed password": "Password hashes", "hash": "Password hashes", "salt": "Password hashes",
    "phone": "Phone numbers", "address": "Physical addresses", "ip address": "IP addresses",
    "vin": "Vehicle identifiers", "dob": "Dates of birth", "license plate": "Vehicle identifiers",
    "social": "Social media profiles", "cryptocurrency address": "Cryptocurrency addresses",
    "url": "Website URLs", "company": "Employers",
}


def _date(v) -> date | None:
    try:
        return date.fromisoformat(str(v)[:10]) if v else None
    except ValueError:
        return None


def scan_from_username_results(username: str, found: list[dict], checked: int) -> ScanResult:
    """found: [{"site": "GitHub", "url": "https://github.com/x"}, ...] from the SSE search."""
    nsfw = {s.name for s in load_sites(include_nsfw=True) if s.nsfw}
    hits = [UsernameHit(platform=f["site"], url=f.get("url", ""),
                        category="adult" if f["site"] in nsfw else categorize(f["site"]))
            for f in found]
    return ScanResult(target=username, target_type="username", username_hits=hits, sites_checked=checked,
                      sources=[SourceStatus(name="Username sweep", status="ok",
                                            detail=f"{checked} sites checked")])


def scan_from_breach_results(term: str, results: list[dict]) -> ScanResult:
    """results: the list returned by breach.lookup()."""
    breaches: dict[str, Breach] = {}
    pastes: list[PasteHit] = []
    sources: list[SourceStatus] = []

    for p in results:
        name = PROVIDER_NAMES.get(p.get("provider"), p.get("provider", "?"))
        if p.get("error"):
            sources.append(SourceStatus(name=name, status="error", detail=p["error"]))
            continue
        if p.get("skipped"):
            sources.append(SourceStatus(name=name, status="skipped", detail=p["skipped"]))
            continue
        sources.append(SourceStatus(name=name, status="ok",
                                    detail=p.get("attribution", "")))
        if p.get("pastes"):
            pastes.append(PasteHit(source=name, title=f"{p['pastes']} paste record(s) reported by {name}"))

        for b in p.get("breaches") or []:
            if p["provider"] == "intelx":
                pastes.append(PasteHit(source="IntelX", title=b.get("name") or "Untitled",
                                       found_date=_date(b.get("date")), bucket=b.get("bucket")))
                continue
            if p["provider"] == "dehashed":
                classes = sorted({_DEHASHED_LABELS.get(t.lower(), t.title()) for t in b.get("data_types", [])})
                if b.get("secrets_exposed") and not any("Password" in c for c in classes):
                    classes.append("Passwords")
            else:
                classes = list(b.get("data_types", []))
                if b.get("secrets_exposed") and not any("password" in c.lower() for c in classes):
                    classes.append("Passwords")
            key = (b.get("name") or "Unknown").strip().lower()
            if key in breaches:  # same breach reported by two providers: merge
                m = breaches[key]
                m.data_classes = sorted(set(m.data_classes) | set(classes))
                m.breach_date = m.breach_date or _date(b.get("date"))
                if name not in m.source:
                    m.source += f", {name}"
            else:
                breaches[key] = Breach(name=b.get("name") or "Unknown", source=name,
                                       breach_date=_date(b.get("date")), data_classes=classes,
                                       is_verified=b.get("verified", True) is not False)

    ttype = "email" if "@" in term else "username"
    return ScanResult(target=term, target_type=ttype, breaches=list(breaches.values()),
                      pastes=pastes, sources=sources)
