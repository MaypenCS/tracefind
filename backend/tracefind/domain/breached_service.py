"""Domain check: has the service at this domain itself been breached? (HIBP free catalogue)"""
from __future__ import annotations

from tracefind.hibp_catalog import ATTRIBUTION, Catalog, breach_age_years
from tracefind.report.models import DomainCheck, Severity


def check_breached_service(domain: str, cat: Catalog | None) -> list[DomainCheck]:
    if cat is None:
        return [DomainCheck(id="breached-service", group="exposure", status="info", severity=Severity.INFO,
                            title="Breach catalogue unavailable",
                            why_it_matters="Couldn't load Have I Been Pwned's breach list. Try again later.")]
    hits = cat.for_domain(domain)
    if not hits:
        return [DomainCheck(id="breached-service", group="exposure", status="pass",
                            title="No known breaches of this domain's service",
                            evidence=[f"Checked against {len(cat)} breaches. {ATTRIBUTION}"])]
    recent = [b for b in hits if (breach_age_years(b) or 99) <= 2]
    creds = [b for b in hits if any("password" in c.lower() for c in b.get("DataClasses") or [])]
    sev = Severity.HIGH if any(b in creds for b in recent) else Severity.MEDIUM
    n = len(hits)
    return [DomainCheck(
        id="breached-service", group="exposure", status="fail", severity=sev,
        title=f"This domain's service appears in {n} known breach{'es' if n != 1 else ''}",
        why_it_matters=("Customer or user data from this service has been published in a breach. Attackers "
                        "reuse those emails and passwords for phishing and account takeovers, and customers "
                        "will ask what was done about it."),
        actions=["Confirm the incident was investigated and closed, and that affected users were told.",
                 "If passwords leaked, make sure every affected account was forced to reset.",
                 "Canadian privacy law (PIPEDA) requires reporting breaches that pose a real risk of "
                 "significant harm. Check that this was done.",
                 "Turn on MFA for customer and staff accounts."],
        evidence=[f"{b.get('Title') or b.get('Name')} ({b.get('BreachDate') or 'date unknown'}, "
                  f"{(b.get('PwnCount') or 0):,} accounts): {', '.join(b.get('DataClasses') or [])}"
                  for b in hits[:15]] + [ATTRIBUTION],
    )]
