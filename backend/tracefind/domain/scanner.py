"""Runs a domain scan: passive checks always, active checks only for verified owners."""
from __future__ import annotations

from typing import Callable, Optional

import httpx

from tracefind.report.models import DomainCheck, DomainResult, ScanResult, Severity, SourceStatus

from . import web
from .breached_service import check_breached_service
from .email_auth import DnsPythonResolver, DnsUnavailable, Resolver, run_email_checks
from .ownership import check_ownership
from .probes import run_probes
from .util import DomainError, normalize_domain, resolve_public


class OwnershipRequired(Exception):
    pass


def make_client() -> httpx.Client:
    return httpx.Client(timeout=10.0, headers={"User-Agent": web.USER_AGENT}, verify=True)


def scan_domain(
    domain: str,
    *,
    secret: bytes,
    active: bool = False,
    resolver: Optional[Resolver] = None,
    client: Optional[httpx.Client] = None,
    cert_fetcher: Callable[[str], web.CertInfo] = web.fetch_cert,
    public_check: Callable[[str], list[str]] = resolve_public,
    sleep: Optional[Callable[[float], None]] = None,
    catalog_loader: Optional[Callable] = None,
) -> ScanResult:
    domain = normalize_domain(domain)
    resolver = resolver or DnsPythonResolver()
    own_client = client is None
    client = client or make_client()
    checks: list[DomainCheck] = []
    sources: list[SourceStatus] = []
    try:
        exists = getattr(resolver, "exists", None)
        if exists is not None:
            try:
                if not exists(domain):
                    raise DomainError(f"{domain} doesn't exist in DNS. Check the spelling.")
            except DnsUnavailable as e:
                raise DomainError("DNS lookups are failing right now, so results would be wrong. "
                                  "Check your internet connection and try again.") from e

        # Ownership first, so an active request without proof fails fast.
        method = check_ownership(domain, secret, resolver, client)
        if active and not method:
            raise OwnershipRequired(domain)

        try:
            checks += run_email_checks(domain, resolver)
            sources.append(SourceStatus(name="DNS (SPF, DKIM, DMARC, MX)", status="ok"))
        except DnsUnavailable as e:
            # Report "couldn't check" rather than a false "no SPF/DMARC".
            sources.append(SourceStatus(name="DNS (SPF, DKIM, DMARC, MX)", status="error", detail=str(e)))

        # Web checks on the bare domain, falling back to www.
        web_host = None
        for host in (domain, f"www.{domain}"):
            try:
                public_check(host)
            except DomainError as e:
                if "private or reserved" in str(e):
                    checks.append(DomainCheck(id="private-ip", group="web", status="info", severity=Severity.INFO,
                                              title=f"{host} points to a private address; web checks skipped",
                                              evidence=[str(e)]))
                    break
                continue
            cert = cert_fetcher(host)
            if cert.ok or not cert.error.startswith("connection failed") or host.startswith("www."):
                web_host = host
                checks += web.check_cert(host, cert)
                break
        if web_host:
            redirect, headers = web.fetch_homepage(web_host, client)
            checks += web.check_headers(web_host, redirect, headers)
            sources.append(SourceStatus(name=f"Website ({web_host})", status="ok"))
        else:
            sources.append(SourceStatus(name="Website", status="skipped", detail="no reachable public web server"))

        subs = web.fetch_subdomains(domain, client)
        checks += web.check_subdomains(domain, subs)
        sources.append(SourceStatus(name="Certificate Transparency (crt.sh)",
                                    status="ok" if subs is not None else "error",
                                    detail="" if subs is not None else "no response"))

        from tracefind.hibp_catalog import load_catalog
        cat = (catalog_loader or load_catalog)(client)
        checks += check_breached_service(domain, cat)
        sources.append(SourceStatus(name="Have I Been Pwned breach catalogue",
                                    status="ok" if cat else "error",
                                    detail="CC BY 4.0" if cat else "couldn't load"))

        ran_active = False
        if active and web_host:
            kwargs = {"sleep": sleep} if sleep else {}
            checks += run_probes(web_host, client, **kwargs)
            ran_active = True
            sources.append(SourceStatus(name="Exposed files and admin pages", status="ok"))
        elif not method:
            sources.append(SourceStatus(name="Exposed files and admin pages", status="skipped",
                                        detail="verify domain ownership to run these checks"))

        return ScanResult(
            target=domain, target_type="domain", sources=sources,
            domain=DomainResult(domain=domain, checks=checks, subdomains=subs or [],
                                ownership_verified=bool(method), active_checks_ran=ran_active),
        )
    finally:
        if own_client:
            client.close()
