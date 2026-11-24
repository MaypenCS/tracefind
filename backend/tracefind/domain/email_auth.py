"""Passive email-authentication checks: SPF, DMARC, DKIM, MX.

Check logic works on plain record strings, so it's testable without DNS.
`run_email_checks()` does the DNS lookups through a resolver you can swap out.
"""
from __future__ import annotations

import re
from typing import Protocol

from tracefind.report.models import DomainCheck, Severity

COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "k1", "k2", "k3", "s1", "s2", "mail", "dkim",
    "smtp", "mandrill", "mxvault", "zoho", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2",
    "fm3", "mailjet", "sendgrid", "s1024", "s2048", "everlytickey1", "cm", "sig1", "ses", "brevo",
    "mailo", "titan1", "hostinger", "pm", "s1-ionos", "s2-ionos",
]
SPF_LOOKUP_TERMS = re.compile(r"^(?:[+\-~?])?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:|redirect=)", re.I)


class DnsUnavailable(Exception):
    """DNS lookups failed (timeout/SERVFAIL). Never treat this as 'no record'."""


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[tuple[int, str]]: ...
    def exists(self, name: str) -> bool: ...


class DnsPythonResolver:
    def __init__(self, timeout: float = 5.0):
        import dns.resolver
        self._r = dns.resolver.Resolver()
        self._r.lifetime = timeout

    def _q(self, name, rtype):
        import dns.exception
        import dns.resolver
        try:
            return self._r.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise DnsUnavailable(f"DNS lookup for {name} failed ({type(e).__name__})") from e

    def exists(self, name: str) -> bool:
        import dns.resolver
        try:
            self._r.resolve(name, "SOA")
            return True
        except dns.resolver.NoAnswer:
            return True          # name exists, just no SOA here (e.g. a subdomain)
        except dns.resolver.NXDOMAIN:
            return False
        except Exception as e:  # noqa: BLE001
            raise DnsUnavailable(f"DNS lookup for {name} failed ({type(e).__name__})") from e

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._q(name, "TXT")]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return sorted((r.preference, str(r.exchange).rstrip(".")) for r in self._q(name, "MX"))


# ---------------------------------------------------------------- SPF

def check_spf(domain: str, txts: list[str]) -> list[DomainCheck]:
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        return [DomainCheck(
            id="spf", group="email", status="fail", severity=Severity.HIGH,
            title="No SPF record: anyone can send email pretending to be this domain",
            why_it_matters=("SPF tells receiving mail servers which servers may send mail for "
                            f"{domain}. Without it, scammers can spoof invoices or password-reset "
                            "emails from your address, and your real mail is more likely to land in spam."),
            actions=["Add a TXT record at the root of the domain listing your mail provider, e.g. "
                     "\"v=spf1 include:_spf.google.com ~all\" for Google Workspace.",
                     "If this domain never sends email, publish \"v=spf1 -all\"."])]
    if len(spf) > 1:
        return [DomainCheck(
            id="spf", group="email", status="fail", severity=Severity.HIGH,
            title="Multiple SPF records: SPF is broken",
            why_it_matters="Having more than one SPF record is an error, so receivers treat SPF as failed.",
            actions=["Merge them into a single TXT record that starts with v=spf1."],
            evidence=spf)]
    rec = spf[0]
    terms = rec.split()[1:]
    all_term = next((t.lower() for t in terms if t.lower().lstrip("+-~?") == "all"), None)
    lookups = sum(1 for t in terms if SPF_LOOKUP_TERMS.match(t))
    out = []
    if all_term in ("+all", "all"):
        out.append(DomainCheck(
            id="spf", group="email", status="fail", severity=Severity.HIGH,
            title="SPF allows every server in the world (+all)",
            why_it_matters="'+all' authorizes any server to send as your domain, which defeats SPF entirely.",
            actions=["Change '+all' to '~all' or '-all'."], evidence=[rec]))
    elif all_term == "?all" or all_term is None:
        out.append(DomainCheck(
            id="spf", group="email", status="fail", severity=Severity.MEDIUM,
            title="SPF is neutral: unauthorized senders aren't rejected",
            why_it_matters="Without a ~all or -all ending, SPF gives receivers no instruction to distrust spoofed mail.",
            actions=["End the record with '~all' (or '-all' once you're sure all senders are listed)."],
            evidence=[rec]))
    else:
        out.append(DomainCheck(id="spf", group="email", status="pass",
                               title=f"SPF record present ({all_term})", evidence=[rec]))
    if lookups > 10:
        out.append(DomainCheck(
            id="spf-lookups", group="email", status="fail", severity=Severity.MEDIUM,
            title=f"SPF needs at least {lookups} DNS lookups (limit is 10)",
            why_it_matters="Above 10 lookups SPF fails with a permanent error, even for your legitimate mail.",
            actions=["Remove includes for services you no longer use, or use an SPF flattening service."],
            evidence=[rec]))
    return out


# ---------------------------------------------------------------- DMARC

def _tags(record: str) -> dict[str, str]:
    out = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def check_dmarc(domain: str, txts: list[str]) -> list[DomainCheck]:
    recs = [t for t in txts if t.lower().replace(" ", "").startswith("v=dmarc1")]
    if not recs:
        return [DomainCheck(
            id="dmarc", group="email", status="fail", severity=Severity.HIGH,
            title="No DMARC record: spoofed email isn't blocked",
            why_it_matters=("DMARC tells Gmail, Outlook and others what to do with mail that fails "
                            "SPF/DKIM. Without it, spoofed messages from your domain are usually delivered. "
                            "Gmail and Yahoo now require DMARC for bulk senders."),
            actions=[f"Add a TXT record at _dmarc.{domain}: \"v=DMARC1; p=none; rua=mailto:dmarc@{domain}\" "
                     "to start monitoring.",
                     "After a few weeks of clean reports, move to p=quarantine, then p=reject."])]
    if len(recs) > 1:
        return [DomainCheck(id="dmarc", group="email", status="fail", severity=Severity.HIGH,
                            title="Multiple DMARC records: DMARC is ignored",
                            why_it_matters="Receivers ignore DMARC entirely when more than one record exists.",
                            actions=["Keep exactly one TXT record at _dmarc."], evidence=recs)]
    rec = recs[0]
    t = _tags(rec)
    p = t.get("p", "").lower()
    out = []
    if p == "none" or p not in ("quarantine", "reject"):
        out.append(DomainCheck(
            id="dmarc", group="email", status="fail", severity=Severity.MEDIUM,
            title="DMARC is in monitoring mode only (p=none)",
            why_it_matters="p=none reports spoofing but doesn't stop it. Spoofed mail is still delivered.",
            actions=["Review the DMARC reports, make sure your real senders pass, then set p=quarantine "
                     "and later p=reject."], evidence=[rec]))
    else:
        out.append(DomainCheck(id="dmarc", group="email", status="pass",
                               title=f"DMARC enforced (p={p})", evidence=[rec]))
        if t.get("pct", "100") != "100":
            out.append(DomainCheck(
                id="dmarc-pct", group="email", status="fail", severity=Severity.LOW,
                title=f"DMARC only applies to {t['pct']}% of mail",
                why_it_matters="The rest of the spoofed mail gets the weaker treatment.",
                actions=["Raise pct to 100 (or remove the pct tag)."], evidence=[rec]))
        sp = t.get("sp", "").lower()
        if sp == "none":
            out.append(DomainCheck(
                id="dmarc-sp", group="email", status="fail", severity=Severity.LOW,
                title="Subdomains are excluded from DMARC (sp=none)",
                why_it_matters="Attackers can spoof mail from made-up subdomains like billing.yourdomain.",
                actions=["Set sp=quarantine or sp=reject, or remove sp so it inherits p."], evidence=[rec]))
    if "rua" not in t:
        out.append(DomainCheck(
            id="dmarc-rua", group="email", status="info", severity=Severity.INFO,
            title="No DMARC reporting address",
            why_it_matters="Without rua= you never see who is sending mail as your domain.",
            actions=["Add rua=mailto:<address> to the DMARC record (a free DMARC report service helps)."],
            evidence=[rec]))
    return out


# ---------------------------------------------------------------- DKIM / MX

def check_dkim(found: dict[str, str]) -> list[DomainCheck]:
    if not found:
        return [DomainCheck(
            id="dkim", group="email", status="info", severity=Severity.INFO,
            title="No DKIM key found on common selectors",
            why_it_matters=("DKIM signs your outgoing mail so it can't be forged or altered. Selector "
                            "names are chosen by your mail provider, so DKIM may exist under a name we "
                            "didn't try."),
            actions=["Check your mail provider's admin console and make sure DKIM signing is turned on."])]
    revoked = [s for s, rec in found.items() if re.search(r"(^|;)\s*p=\s*(;|$)", rec)]
    out = [DomainCheck(id="dkim", group="email", status="pass",
                       title=f"DKIM key found ({', '.join(sorted(found))})",
                       evidence=[f"{s}._domainkey" for s in sorted(found)])]
    if revoked:
        out.append(DomainCheck(id="dkim-revoked", group="email", status="info", severity=Severity.INFO,
                               title=f"Revoked DKIM key published ({', '.join(revoked)})",
                               why_it_matters="An empty p= means the key was revoked. Fine if intended.",
                               actions=["Remove the record if that selector is no longer used."]))
    return out


def check_mx(domain: str, mx: list[tuple[int, str]], has_strict_spf: bool, has_reject_dmarc: bool) -> list[DomainCheck]:
    if mx == [(0, "")] or mx == [(0, ".")]:
        return [DomainCheck(id="mx", group="email", status="pass", title="Null MX: domain declares it receives no email")]
    if mx:
        return [DomainCheck(id="mx", group="email", status="pass",
                            title=f"Mail servers configured ({len(mx)})",
                            evidence=[f"{p} {h}" for p, h in mx])]
    if has_strict_spf and has_reject_dmarc:
        return [DomainCheck(id="mx", group="email", status="pass",
                            title="No mail servers, and the domain is locked against spoofing")]
    return [DomainCheck(
        id="mx-parked", group="email", status="fail", severity=Severity.MEDIUM,
        title="Domain receives no email but isn't locked against spoofing",
        why_it_matters="Domains that don't use email are favourite spoofing targets because no one watches them.",
        actions=["Publish SPF \"v=spf1 -all\" and DMARC \"v=DMARC1; p=reject\" to declare that "
                 "nothing sends mail for this domain."])]


def run_email_checks(domain: str, resolver: Resolver) -> list[DomainCheck]:
    root_txt = resolver.txt(domain)
    spf = check_spf(domain, root_txt)
    dmarc_txt = resolver.txt(f"_dmarc.{domain}")
    dmarc = check_dmarc(domain, dmarc_txt)
    found = {}
    for sel in COMMON_DKIM_SELECTORS:
        recs = [r for r in resolver.txt(f"{sel}._domainkey.{domain}") if "p=" in r]
        if recs:
            found[sel] = recs[0]
    strict_spf = any(t.lower().startswith("v=spf1") and t.lower().rstrip().endswith("-all") for t in root_txt)
    reject = any(_tags(t).get("p", "").lower() == "reject" for t in dmarc_txt)
    return spf + dmarc + check_dkim(found) + check_mx(domain, resolver.mx(domain), strict_spf, reject)
