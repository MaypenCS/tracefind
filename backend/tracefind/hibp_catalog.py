"""Have I Been Pwned's free breach catalogue (no API key).

HIBP publishes metadata for every breach it has loaded (name, title, domain, breach date, data
classes, verified flag) at /api/v3/breaches. Its terms allow this catalogue for any lawful purpose
under CC BY 4.0, so anything shown from it is credited to "Have I Been Pwned".

tracefind uses it to:
  * fill in exact dates and data types for breaches found by other providers
  * give one name to the same breach across providers (XposedOrNot's "LinkedIn2021" -> HIBP's title)
  * list breaches of a domain's own service in the Domain tab
The catalogue is cached on disk for 24 hours.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import date
from pathlib import Path
from typing import Optional

import httpx

CATALOG_URL = "https://haveibeenpwned.com/api/v3/breaches"
CACHE = Path(os.getenv("TRACEFIND_CACHE_DIR") or Path(__file__).resolve().parent / "data") / "hibp_breaches.json"
MAX_AGE_S = 24 * 3600
ATTRIBUTION = "Breach details from Have I Been Pwned (haveibeenpwned.com), CC BY 4.0"
UA = "tracefind/1.1 (Maypen Cybersecurity)"


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


class Catalog:
    def __init__(self, breaches: list[dict]):
        self.breaches = breaches
        self.by_name: dict[str, dict] = {}
        self.by_domain: dict[str, list[dict]] = {}
        for b in breaches:
            for key in (b.get("Name"), b.get("Title")):
                if key:
                    self.by_name.setdefault(_norm(key), b)
            d = (b.get("Domain") or "").lower()
            if d:
                self.by_domain.setdefault(d, []).append(b)

    def __len__(self):
        return len(self.breaches)

    def match(self, name: str, domain: str | None = None, year: str | None = None) -> Optional[dict]:
        """Find the HIBP entry for a breach reported by another provider."""
        n = _norm(name)
        if n in self.by_name:
            return self.by_name[n]
        # "LinkedIn2021" / "Adobe-2013": strip a trailing year and try again, preferring that year
        m = re.match(r"^(.*?)(19|20)(\d\d)$", n)
        if m and m.group(1):
            base, y = m.group(1), m.group(2) + m.group(3)
            year = year or y
            cands = list({b["Name"]: b for k, b in self.by_name.items() if k.startswith(base)}.values())
            if cands:
                same_year = [b for b in cands if (b.get("BreachDate") or "").startswith(year)]
                if len(same_year) == 1:
                    return same_year[0]
                if base in self.by_name and len(cands) == 1:
                    return cands[0]
        # same service domain + same year
        if domain:
            cands = self.by_domain.get(domain.lower().removeprefix("www."), [])
            if year:
                cands = [b for b in cands if (b.get("BreachDate") or "").startswith(str(year))]
            if len(cands) == 1:
                return cands[0]
        return None

    def for_domain(self, domain: str) -> list[dict]:
        """Breaches of the service at this domain (or its subdomains)."""
        d = domain.lower().removeprefix("www.")
        out = [b for dom, bs in self.by_domain.items() if dom == d or dom.endswith("." + d) for b in bs]
        return sorted(out, key=lambda b: b.get("BreachDate") or "", reverse=True)


def _read_cache(max_age: float) -> Optional[list[dict]]:
    try:
        if CACHE.exists() and (max_age < 0 or time.time() - CACHE.stat().st_mtime < max_age):
            return json.loads(CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return None


def load_catalog(client: httpx.Client | None = None, max_age: float = MAX_AGE_S) -> Optional[Catalog]:
    """Fresh cache -> download -> stale cache -> None. Never raises."""
    data = _read_cache(max_age)
    if data is None:
        try:
            own = client is None
            c = client or httpx.Client(timeout=20)
            try:
                r = c.get(CATALOG_URL, headers={"User-Agent": UA})
                r.raise_for_status()
                data = r.json()
            finally:
                if own:
                    c.close()
            if isinstance(data, list) and len(data) > 100:
                CACHE.parent.mkdir(parents=True, exist_ok=True)
                CACHE.write_text(json.dumps(data), encoding="utf-8")
        except (httpx.HTTPError, ValueError, OSError):
            data = _read_cache(-1)  # offline: fall back to an old copy
    return Catalog(data) if isinstance(data, list) and data else None


def enrich(entry: dict, cat: Catalog, year: str | None = None) -> dict:
    """Return a copy of a provider breach entry with HIBP's title, exact date and data types."""
    b = cat.match(entry.get("name") or "", entry.get("domain"), year)
    if not b:
        return entry
    out = dict(entry)
    out["name"] = b.get("Title") or b.get("Name") or entry.get("name")
    out["date"] = b.get("BreachDate") or entry.get("date")
    out["domain"] = b.get("Domain") or entry.get("domain")
    out["data_types"] = sorted(set(entry.get("data_types") or []) | set(b.get("DataClasses") or []))
    out["accounts"] = entry.get("accounts") or b.get("PwnCount")
    out["verified"] = b.get("IsVerified", entry.get("verified"))
    out["hibp_name"] = b.get("Name")
    if any("password" in t.lower() for t in out["data_types"]):
        out["secrets_exposed"] = True
    return out


def breach_age_years(b: dict) -> Optional[float]:
    try:
        return (date.today() - date.fromisoformat(b["BreachDate"])).days / 365.25
    except (KeyError, TypeError, ValueError):
        return None
