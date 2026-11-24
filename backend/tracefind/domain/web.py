"""Passive web checks: TLS certificate, HTTPS redirect, security headers, public subdomains.

These only do what a normal visitor's browser does (load the homepage), plus a lookup in
public Certificate Transparency logs (crt.sh). Check logic is split from the network calls.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx

from tracefind.report.models import DomainCheck, Severity

from tracefind.report.brand import brand_domain

USER_AGENT = (f"TraceFind/1.0 (+https://{brand_domain()}; exposure check)" if brand_domain()
              else "TraceFind/1.0 (exposure check)")
INTERESTING_SUBDOMAIN_WORDS = ("dev", "staging", "stage", "test", "uat", "qa", "admin", "old", "backup",
                               "beta", "internal", "vpn", "jenkins", "git", "gitlab", "jira", "grafana",
                               "kibana", "phpmyadmin", "cpanel", "webmail", "db", "sql", "ftp")


# ---------------------------------------------------------------- TLS

@dataclass
class CertInfo:
    ok: bool                       # chain + hostname verified
    error: str = ""
    not_after: Optional[datetime] = None
    issuer: str = ""
    tls_version: str = ""


def fetch_cert(host: str, port: int = 443, timeout: float = 8.0) -> CertInfo:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
                issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
                return CertInfo(ok=True, not_after=exp, issuer=issuer, tls_version=s.version() or "")
    except ssl.SSLCertVerificationError as e:
        return CertInfo(ok=False, error=e.verify_message or str(e))
    except (OSError, ssl.SSLError) as e:
        return CertInfo(ok=False, error=f"connection failed: {e.__class__.__name__}")


def check_cert(host: str, c: CertInfo, now: datetime | None = None) -> list[DomainCheck]:
    now = now or datetime.now(timezone.utc)
    if not c.ok:
        if c.error.startswith("connection failed"):
            return [DomainCheck(id="https", group="web", status="info", severity=Severity.INFO,
                                title=f"No HTTPS service reachable on {host}",
                                why_it_matters="Couldn't connect on port 443. Fine if this domain has no website.",
                                actions=["If there should be a website here, make sure HTTPS is enabled."],
                                evidence=[c.error])]
        return [DomainCheck(
            id="cert", group="web", status="fail", severity=Severity.HIGH,
            title="HTTPS certificate is invalid",
            why_it_matters=("Visitors get a full-page browser warning, and people get used to clicking "
                            "through warnings, which is exactly what attackers rely on."),
            actions=["Renew or reissue the certificate for the correct hostname (Let's Encrypt is free and auto-renews)."],
            evidence=[c.error])]
    days = (c.not_after - now).days
    ev = [f"Expires {c.not_after:%Y-%m-%d} ({days} days)", f"Issuer: {c.issuer or 'unknown'}",
          f"Protocol: {c.tls_version}"]
    out = []
    if days < 14:
        out.append(DomainCheck(id="cert", group="web", status="fail",
                               severity=Severity.MEDIUM if days >= 0 else Severity.HIGH,
                               title=f"HTTPS certificate expires in {days} days",
                               why_it_matters="When it expires, browsers block the site with a security warning.",
                               actions=["Renew now and set up automatic renewal."], evidence=ev))
    else:
        out.append(DomainCheck(id="cert", group="web", status="pass",
                               title=f"Valid HTTPS certificate ({days} days left)", evidence=ev))
    if c.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(DomainCheck(id="tls-old", group="web", status="fail", severity=Severity.MEDIUM,
                               title=f"Outdated encryption protocol ({c.tls_version})",
                               why_it_matters="TLS 1.0 and 1.1 have known weaknesses and are retired by browsers.",
                               actions=["Disable TLS 1.0/1.1 on the server; allow TLS 1.2 and 1.3 only."]))
    return out


# ---------------------------------------------------------------- headers

def check_headers(host: str, http_redirects_to_https: Optional[bool], headers: dict[str, str]) -> list[DomainCheck]:
    h = {k.lower(): v for k, v in headers.items()}
    out = []
    if http_redirects_to_https is False:
        out.append(DomainCheck(
            id="http-redirect", group="web", status="fail", severity=Severity.MEDIUM,
            title="Plain HTTP doesn't redirect to HTTPS",
            why_it_matters="Visitors who type the address without https:// get an unencrypted page that can be tampered with.",
            actions=["Redirect all http:// requests to https:// (most hosts have a one-click setting)."]))
    elif http_redirects_to_https:
        out.append(DomainCheck(id="http-redirect", group="web", status="pass", title="HTTP redirects to HTTPS"))
    if not headers:
        return out
    if "strict-transport-security" in h:
        out.append(DomainCheck(id="hsts", group="web", status="pass", title="HSTS enabled"))
    else:
        out.append(DomainCheck(
            id="hsts", group="web", status="fail", severity=Severity.LOW,
            title="HSTS header missing",
            why_it_matters="HSTS tells browsers to always use HTTPS for your site, which blocks downgrade attacks on public Wi-Fi.",
            actions=["Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"]))
    missing = []
    if "x-content-type-options" not in h:
        missing.append("X-Content-Type-Options: nosniff")
    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options: DENY (or CSP frame-ancestors)")
    if not csp:
        missing.append("Content-Security-Policy")
    if "referrer-policy" not in h:
        missing.append("Referrer-Policy: strict-origin-when-cross-origin")
    if missing:
        out.append(DomainCheck(
            id="headers", group="web", status="fail", severity=Severity.LOW,
            title=f"{len(missing)} recommended security header{'s' if len(missing) != 1 else ''} missing",
            why_it_matters="These headers limit clickjacking, content sniffing and cross-site scripting damage.",
            actions=["Add the missing headers in your web server, host or CDN settings."], evidence=missing))
    else:
        out.append(DomainCheck(id="headers", group="web", status="pass", title="Recommended security headers present"))
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if any(ch.isdigit() for ch in server + powered):
        out.append(DomainCheck(
            id="version-leak", group="web", status="fail", severity=Severity.LOW,
            title="Server software version is advertised",
            why_it_matters="Version numbers let attackers match your server to known vulnerabilities instantly.",
            actions=["Hide version details (e.g. 'server_tokens off' in nginx, 'expose_php = Off' in PHP)."],
            evidence=[x for x in (f"Server: {server}" if server else "", f"X-Powered-By: {powered}" if powered else "") if x]))
    return out


def fetch_homepage(host: str, client: httpx.Client) -> tuple[Optional[bool], dict[str, str]]:
    """Returns (http_redirects_to_https, https_headers)."""
    redirect = None
    try:
        r = client.get(f"http://{host}/", follow_redirects=False)
        loc = r.headers.get("location", "")
        redirect = r.is_redirect and loc.lower().startswith("https://")
    except httpx.HTTPError:
        pass
    try:
        r = client.get(f"https://{host}/", follow_redirects=True)
        return redirect, dict(r.headers)
    except httpx.HTTPError:
        return redirect, {}


# ---------------------------------------------------------------- subdomains (CT logs)

def parse_crtsh(domain: str, rows: list[dict]) -> list[str]:
    names = set()
    for row in rows:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.").rstrip(".")
            if n and (n == domain or n.endswith("." + domain)) and n != domain:
                names.add(n)
    return sorted(names)


def fetch_subdomains(domain: str, client: httpx.Client) -> Optional[list[str]]:
    try:
        r = client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=25)
        r.raise_for_status()
        return parse_crtsh(domain, r.json())
    except (httpx.HTTPError, ValueError):
        return None


def check_subdomains(domain: str, subs: Optional[list[str]]) -> list[DomainCheck]:
    if subs is None:
        return [DomainCheck(id="subdomains", group="exposure", status="info", severity=Severity.INFO,
                            title="Subdomain lookup unavailable",
                            why_it_matters="crt.sh (Certificate Transparency logs) didn't respond. Try again later.")]
    if not subs:
        return [DomainCheck(id="subdomains", group="exposure", status="pass",
                            title="No extra subdomains in public certificate logs")]
    flagged = [s for s in subs if any(w in s[: -len(domain) - 1].replace("-", ".").split(".")
                                      for w in INTERESTING_SUBDOMAIN_WORDS)]
    out = [DomainCheck(id="subdomains", group="exposure", status="pass",
                       title=f"{len(subs)} subdomain{'s' if len(subs) != 1 else ''} in public certificate logs",
                       evidence=subs[:60])]
    if flagged:
        out.append(DomainCheck(
            id="subdomains-sensitive", group="exposure", status="fail", severity=Severity.LOW,
            title=f"{len(flagged)} subdomain{'s' if len(flagged) != 1 else ''} look like dev, admin or internal systems",
            why_it_matters=("Every HTTPS certificate is published publicly, so attackers can list these too. "
                            "Test, staging and admin systems are often less protected than the main site."),
            actions=["Confirm each one is still needed. Shut down old ones and delete their DNS records.",
                     "Put admin, staging and internal tools behind a login, VPN or IP allow-list."],
            evidence=flagged))
    return out
