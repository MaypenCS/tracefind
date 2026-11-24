"""Turns raw scan results into prioritized, plain-English findings.

Rules of thumb:
  * Password / credential data in a breach        -> HIGH
  * Sensitive personal or financial data leaked   -> MEDIUM
  * Contact-only data leaked (email, name)        -> LOW
  * Paste / leak-site mentions                    -> MEDIUM
  * Username on a sensitive or unusual category   -> MEDIUM (verify: forgotten account or impersonation)
  * Username on a mainstream platform             -> LOW   (verify it's yours)
Username hits are *leads*, never proof — every finding says so.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import date

from .diff import ScanDiff, diff_scans
from .models import Breach, ExposureReport, Finding, ScanResult, Severity

CREDENTIAL_KEYWORDS = ("password", "hash", "credential", "auth token", "security question", "pin")
SENSITIVE_KEYWORDS = (
    "phone", "physical address", "home address", "postal address", "mailing address",
    "date of birth", "dob", "credit", "card", "bank", "financial",
    "social security", "sin", "passport", "government", "driver", "health", "medical",
    "ip address", "geographic", "location", "income", "salary",
)
SENSITIVE_CATEGORIES = {"dating", "adult", "crypto", "finance", "marketplace"}
CATEGORY_LABELS = {
    "social": "Social", "professional": "Professional", "developer": "Developer",
    "gaming": "Gaming", "creative": "Creative", "forum": "Forums", "dating": "Dating",
    "adult": "Adult", "crypto": "Crypto", "finance": "Finance",
    "marketplace": "Marketplaces", "other": "Other",
}
LARGE_FOOTPRINT = 25


def _has(classes: list[str], keywords: tuple[str, ...]) -> list[str]:
    # Whole-word match so "pin" doesn't hit "spinning" and "sin" doesn't hit "business".
    pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in keywords) + r")(e?s)?\b", re.I)
    return [c for c in classes if pattern.search(c)]


def _years_ago(d: date | None) -> str:
    if not d:
        return "date unknown"
    yrs = (date.today() - d).days // 365
    return "within the last year" if yrs < 1 else f"about {yrs} year{'s' if yrs != 1 else ''} ago"


def _score_breach(i: int, b: Breach) -> Finding:
    creds = _has(b.data_classes, CREDENTIAL_KEYWORDS)
    sensitive = _has(b.data_classes, SENSITIVE_KEYWORDS)
    leaked = ", ".join(b.data_classes) or "unspecified data"
    when = _years_ago(b.breach_date)
    evidence = [f"Source: {b.source}", f"Breach date: {b.breach_date or 'unknown'} ({when})",
                f"Exposed data types: {leaked}"]
    if not b.is_verified:
        evidence.append("Breach is unverified by the source — treat with caution")

    if creds:
        return Finding(
            id=f"breach-{i}", severity=Severity.HIGH, category="breach",
            title=f"Password data exposed in the {b.name} breach",
            why_it_matters=(
                f"{b.name} leaked {', '.join(creds).lower()} {when}. Attackers try leaked "
                "passwords on other sites (credential stuffing), so any account that reused "
                "this password is at risk — even if the breached site itself no longer matters to you."
            ),
            actions=[
                f"Change your {b.name} password if the account still exists.",
                "Change the password on every other account that used the same or a similar password.",
                "Turn on two-factor authentication (an authenticator app, not SMS, where possible).",
                "Move to a password manager so every account gets a unique password.",
            ],
            evidence=evidence,
        )
    if sensitive:
        return Finding(
            id=f"breach-{i}", severity=Severity.MEDIUM, category="breach",
            title=f"Personal details exposed in the {b.name} breach",
            why_it_matters=(
                f"{b.name} leaked {', '.join(sensitive).lower()} {when}. This kind of data "
                "is used to make phishing messages and scam calls sound convincing."
            ),
            actions=[
                "Be extra suspicious of calls, texts or emails that quote your personal details.",
                "If financial data was involved, review statements and consider a credit alert "
                "(Equifax / TransUnion in Canada).",
                "Change the password for this service as a precaution.",
            ],
            evidence=evidence,
        )
    return Finding(
        id=f"breach-{i}", severity=Severity.LOW, category="breach",
        title=f"Contact details exposed in the {b.name} breach",
        why_it_matters=(
            f"{b.name} leaked {leaked.lower()} {when}. No passwords were reported, but your "
            "address is now on lists that spammers and phishers use."
        ),
        actions=["Expect more spam and phishing to this address — don't click unexpected links.",
                 "Change the password for this service as a precaution."],
        evidence=evidence,
    )


def build_findings(scan: ScanResult) -> list[Finding]:
    findings: list[Finding] = [_score_breach(i, b) for i, b in enumerate(scan.breaches)]

    if scan.pastes:
        findings.append(Finding(
            id="pastes", severity=Severity.MEDIUM, category="paste",
            title=f"Mentioned in {len(scan.pastes)} paste or leak record{'s' if len(scan.pastes) != 1 else ''}",
            why_it_matters=(
                "Your identifier appears in text dumps on paste or leak sites. These are often "
                "combo lists (email + password pairs) shared between attackers."
            ),
            actions=["Treat this like a password breach: change reused passwords and enable 2FA.",
                     "Watch for login alerts from your important accounts."],
            evidence=[f"{p.source}: {p.title} ({p.found_date or 'date unknown'})" for p in scan.pastes[:10]],
        ))

    by_cat: dict[str, list] = defaultdict(list)
    for h in scan.username_hits:
        by_cat[h.category if h.category in CATEGORY_LABELS else "other"].append(h)

    sensitive_hits = [h for c in SENSITIVE_CATEGORIES for h in by_cat.get(c, [])]
    if sensitive_hits:
        findings.append(Finding(
            id="username-sensitive", severity=Severity.MEDIUM, category="username",
            title=f"Your username appears on {len(sensitive_hits)} sensitive or unusual site{'s' if len(sensitive_hits) != 1 else ''}",
            why_it_matters=(
                "Accounts on dating, adult, crypto, finance or marketplace sites are a common "
                "target for impersonation and scams. If these aren't yours, someone may be "
                "using your handle; if they are, they may be forgotten accounts worth closing."
            ),
            actions=["Open each link and confirm whether the account is yours.",
                     "Close accounts you no longer use.",
                     "Report impersonation to the platform if an account isn't yours."],
            evidence=[f"{h.platform} ({CATEGORY_LABELS.get(h.category, 'Other')}): {h.url}" for h in sensitive_hits],
        ))

    mainstream = [h for c, hs in by_cat.items() if c not in SENSITIVE_CATEGORIES for h in hs]
    if mainstream:
        findings.append(Finding(
            id="username-mainstream", severity=Severity.LOW, category="username",
            title=f"Your username appears on {len(mainstream)} mainstream platform{'s' if len(mainstream) != 1 else ''}",
            why_it_matters=(
                "Using one handle everywhere lets anyone link your accounts together into a "
                "profile of you. Some matches may belong to other people with the same username."
            ),
            actions=["Confirm which accounts are yours and close the ones you've forgotten.",
                     "Review privacy settings on the ones you keep.",
                     "Consider separate handles for personal and professional accounts."],
            evidence=[f"{h.platform}: {h.url}" for h in mainstream[:40]],
        ))

    if scan.domain:
        for c in scan.domain.checks:
            if c.status != "pass":
                findings.append(Finding(id=f"domain-{c.id}", severity=c.severity, category="domain",
                                        title=c.title, why_it_matters=c.why_it_matters,
                                        actions=c.actions, evidence=c.evidence))

    if len(scan.username_hits) >= LARGE_FOOTPRINT:
        findings.append(Finding(
            id="footprint", severity=Severity.INFO, category="footprint",
            title="Large online footprint",
            why_it_matters=(f"{len(scan.username_hits)} sites matched this username. A large "
                            "footprint makes you easier to profile and harder to monitor."),
            actions=["Prioritize closing old accounts that still hold personal data."],
        ))

    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings


def build_checklist(findings: list[Finding]) -> list[str]:
    """De-duplicated action list, highest-severity first."""
    seen, out = set(), []
    for f in findings:
        for a in f.actions:
            key = a.lower()
            if key not in seen:
                seen.add(key)
                out.append(a)
    return out


def _change_findings(findings: list[Finding], d: ScanDiff) -> list[Finding]:
    """Flag what's new since the last scan."""
    new_names = {b.name.strip().lower() for b in d.new_breaches}
    for f in findings:
        if f.category == "breach" and any(f.title.lower().endswith(f"the {n} breach") for n in new_names):
            f.title = f"NEW: {f.title}"
            f.evidence.insert(0, "First seen in this scan")
    extra = []
    if d.new_accounts:
        sensitive = [h for h in d.new_accounts if h.category in SENSITIVE_CATEGORIES]
        n = len(d.new_accounts)
        extra.append(Finding(
            id="new-accounts", severity=Severity.MEDIUM if sensitive else Severity.LOW, category="username",
            title=f"NEW: {n} account{'s' if n != 1 else ''} using your username since {d.previous_scanned_at:%b %d, %Y}",
            why_it_matters=(
                "These accounts didn't appear in your previous scan. If you didn't create them, "
                "someone may be impersonating you or squatting your handle."
                + (" Some are on sensitive sites (dating, crypto, finance or marketplaces)." if sensitive else "")
            ),
            actions=["Check each new account. If it isn't yours, report it to the platform as impersonation.",
                     "Warn friends and followers if an impersonator is contacting people."],
            evidence=[f"{h.platform}: {h.url}" for h in d.new_accounts],
        ))
    return extra


def build_report(scan: ScanResult, previous: ScanResult | None = None,
                 previous_id: int | None = None, current_id: int | None = None) -> ExposureReport:
    findings = build_findings(scan)
    changes = None
    if previous is not None:
        changes = diff_scans(previous, scan, previous_id, current_id)
        findings += _change_findings(findings, changes)
        findings.sort(key=lambda f: f.severity.rank, reverse=True)
    counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
    overall = max((f.severity for f in findings), key=lambda s: s.rank, default=Severity.INFO)

    if scan.target_type == "domain":
        summary = {
            Severity.HIGH: "Action needed. This domain has a serious issue that attackers actively look for. "
                           "Fix the high-priority items first.",
            Severity.MEDIUM: "Some weaknesses found. The domain can be abused (e.g. for email spoofing) "
                             "until the medium items are fixed.",
            Severity.LOW: "Good baseline. A few hardening steps are recommended.",
            Severity.INFO: "No significant problems found in the checks that ran.",
        }[overall]
    elif overall == Severity.HIGH:
        summary = ("Action needed. At least one breach exposed password data. Start with the "
                   "high-priority items below. They take about 15–30 minutes.")
    elif overall == Severity.MEDIUM:
        summary = ("Some exposure worth reviewing. No leaked passwords were found, but personal "
                   "details or unusual accounts need a look.")
    elif overall == Severity.LOW:
        summary = "Low exposure. A few routine clean-up steps are recommended."
    else:
        summary = "No significant exposure found in the sources that were checked."

    unverified = [f"{s.name}: {s.status.replace('_', ' ')}{' — ' + s.detail if s.detail else ''}"
                  for s in scan.sources if s.status != "ok"]
    if scan.target_type != "domain":
        unverified.append("Username matches are based on public profile URLs and can include false "
                          "positives. Verify ownership before acting.")
    else:
        unverified.append("DKIM keys are only found when a common selector name is used. Your provider "
                          "may use a different one.")
    if scan.domain and not scan.domain.active_checks_ran:
        unverified.append("Exposed-file and admin-page checks did not run. They need domain "
                          "ownership verification.")
    if scan.target_type == "username":
        unverified.append("Breach checks are most accurate for email addresses; a username-only "
                          "scan may miss breaches.")

    rid = hashlib.sha256(f"{scan.target}|{scan.scanned_at.isoformat()}".encode()).hexdigest()[:10].upper()
    return ExposureReport(scan=scan, overall=overall, summary=summary, findings=findings,
                          counts=counts, checklist=build_checklist(findings),
                          unverified=unverified, report_id=f"TF-{rid}",
                          changes=changes, changes_summary=changes.summary() if changes else [])
