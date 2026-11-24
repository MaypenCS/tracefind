from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tracefind.domain import router as domain_router_mod
from tracefind.domain.email_auth import check_dkim, check_dmarc, check_mx, check_spf
from tracefind.domain.ownership import token_for
from tracefind.domain.probes import run_probes
from tracefind.domain.scanner import OwnershipRequired, scan_domain
from tracefind.domain.util import DomainError, normalize_domain
from tracefind.domain.web import CertInfo, check_cert, check_headers, check_subdomains, parse_crtsh
from tracefind.report.diff import diff_scans
from tracefind.report.render import render_html
from tracefind.report.scoring import build_report

SECRET = b"test-secret"
D = "example.ca"


def sev(checks, cid):
    c = next(c for c in checks if c.id == cid)
    return c.status, c.severity.value


# ---------------------------------------------------------------- input

@pytest.mark.parametrize("raw,expected", [
    ("Example.CA", "example.ca"), ("https://www.example.ca/path?x=1", "www.example.ca"),
    ("example.ca.", "example.ca"), ("example.ca:8443", "example.ca"), ("bücher.de", "xn--bcher-kva.de"),
])
def test_normalize_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "192.168.1.1", "printer.local", "nodot", "a..b.com", "-x.com"])
def test_normalize_rejects(raw):
    with pytest.raises(DomainError):
        normalize_domain(raw)


# ---------------------------------------------------------------- SPF / DMARC / DKIM / MX

def test_spf_cases():
    assert sev(check_spf(D, []), "spf") == ("fail", "high")
    assert sev(check_spf(D, ["v=spf1 -all", "v=spf1 ~all"]), "spf") == ("fail", "high")
    assert sev(check_spf(D, ["v=spf1 +all"]), "spf") == ("fail", "high")
    assert sev(check_spf(D, ["v=spf1 include:x.com ?all"]), "spf") == ("fail", "medium")
    assert sev(check_spf(D, ["v=spf1 include:x.com"]), "spf") == ("fail", "medium")
    assert sev(check_spf(D, ["google-site-verification=abc", "v=spf1 include:_spf.google.com ~all"]), "spf")[0] == "pass"
    many = "v=spf1 " + " ".join(f"include:s{i}.com" for i in range(11)) + " -all"
    assert sev(check_spf(D, [many]), "spf-lookups") == ("fail", "medium")


def test_dmarc_cases():
    assert sev(check_dmarc(D, []), "dmarc") == ("fail", "high")
    assert sev(check_dmarc(D, ["v=DMARC1; p=none; rua=mailto:a@b.c"]), "dmarc") == ("fail", "medium")
    ok = check_dmarc(D, ["v=DMARC1; p=reject; rua=mailto:a@b.c"])
    assert sev(ok, "dmarc")[0] == "pass" and len(ok) == 1
    partial = check_dmarc(D, ["v=DMARC1; p=quarantine; pct=50; sp=none"])
    assert sev(partial, "dmarc-pct") == ("fail", "low")
    assert sev(partial, "dmarc-sp") == ("fail", "low")
    assert sev(partial, "dmarc-rua")[0] == "info"


def test_dkim_and_mx():
    assert sev(check_dkim({}), "dkim") == ("info", "info")
    assert sev(check_dkim({"google": "v=DKIM1; k=rsa; p=MIIB"}), "dkim")[0] == "pass"
    assert any(c.id == "dkim-revoked" for c in check_dkim({"old": "v=DKIM1; p="}))
    assert sev(check_mx(D, [(10, "mx.x.com")], False, False), "mx")[0] == "pass"
    assert sev(check_mx(D, [], False, False), "mx-parked") == ("fail", "medium")
    assert sev(check_mx(D, [], True, True), "mx")[0] == "pass"
    assert sev(check_mx(D, [(0, "")], False, False), "mx")[0] == "pass"


# ---------------------------------------------------------------- web

NOW = datetime(2026, 11, 23, tzinfo=timezone.utc)


def test_cert_cases():
    good = CertInfo(ok=True, not_after=NOW + timedelta(days=60), issuer="Let's Encrypt", tls_version="TLSv1.3")
    assert sev(check_cert(D, good, NOW), "cert")[0] == "pass"
    soon = CertInfo(ok=True, not_after=NOW + timedelta(days=5), tls_version="TLSv1.3")
    assert sev(check_cert(D, soon, NOW), "cert") == ("fail", "medium")
    expired = CertInfo(ok=True, not_after=NOW - timedelta(days=1), tls_version="TLSv1.2")
    assert sev(check_cert(D, expired, NOW), "cert") == ("fail", "high")
    assert sev(check_cert(D, CertInfo(ok=False, error="hostname mismatch"), NOW), "cert") == ("fail", "high")
    assert sev(check_cert(D, CertInfo(ok=False, error="connection failed: TimeoutError"), NOW), "https")[0] == "info"
    old = CertInfo(ok=True, not_after=NOW + timedelta(days=90), tls_version="TLSv1.1")
    assert sev(check_cert(D, old, NOW), "tls-old") == ("fail", "medium")


def test_headers_cases():
    bad = check_headers(D, False, {"Server": "Apache/2.4.41", "Content-Type": "text/html"})
    assert sev(bad, "http-redirect") == ("fail", "medium")
    assert sev(bad, "hsts") == ("fail", "low")
    assert sev(bad, "headers") == ("fail", "low")
    assert sev(bad, "version-leak") == ("fail", "low")
    good = check_headers(D, True, {
        "Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer", "Server": "cloudflare"})
    assert all(c.status == "pass" for c in good)


def test_subdomains():
    rows = [{"name_value": "*.example.ca\nexample.ca"}, {"name_value": "dev.example.ca\nshop.example.ca"},
            {"name_value": "evil-example.ca\nstaging-api.example.ca"}]
    subs = parse_crtsh(D, rows)
    assert subs == ["dev.example.ca", "shop.example.ca", "staging-api.example.ca"]
    checks = check_subdomains(D, subs)
    flagged = next(c for c in checks if c.id == "subdomains-sensitive")
    assert flagged.evidence == ["dev.example.ca", "staging-api.example.ca"]
    assert sev(check_subdomains(D, None), "subdomains")[0] == "info"


# ---------------------------------------------------------------- probes (mocked server)

def site(files: dict[str, tuple[int, bytes]], soft404: bool = False):
    def handler(req: httpx.Request):
        path = req.url.path
        if path in files:
            code, body = files[path]
            return httpx.Response(code, content=body)
        if soft404:
            return httpx.Response(200, content=b"<html>Welcome to our homepage</html>")
        return httpx.Response(404, content=b"not found")
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_probes_find_real_exposures():
    c = site({
        "/.env": (200, b"APP_KEY=base64:xyz\nDB_PASSWORD=hunter2\nDB_HOST=localhost\n"),
        "/.git/HEAD": (200, b"ref: refs/heads/main\n"),
        "/wp-login.php": (200, b'<form><input type="password" name="pwd"></form>'),
        "/.well-known/security.txt": (200, b"Contact: mailto:security@example.ca\n"),
    })
    checks = run_probes(D, c, sleep=lambda s: None)
    titles = {x.title for x in checks if x.status == "fail"}
    assert "Environment file (.env) is public" in titles
    assert "Git repository is public (.git)" in titles
    assert any(x.id == "login-pages" for x in checks)
    assert sev(checks, "security-txt")[0] == "pass"
    assert "hunter2" not in str([x.model_dump() for x in checks])  # contents never stored


def test_probes_ignore_soft_404():
    checks = run_probes(D, site({}, soft404=True), sleep=lambda s: None)
    assert not any(x.status == "fail" for x in checks)
    assert any(x.id == "exposed-files" and x.status == "pass" for x in checks)


def test_probe_signature_rejects_html_env():
    c = site({"/.env": (200, b"<html>APP_KEY=1\nDB=2</html>")})
    assert not any(x.title.startswith("Environment") for x in run_probes(D, c, sleep=lambda s: None))


# ---------------------------------------------------------------- full scan (all network faked)

class FakeResolver:
    def __init__(self, txt=None, mx=None):
        self._txt, self._mx = txt or {}, mx or []

    def txt(self, name):
        return self._txt.get(name, [])

    def mx(self, name):
        return self._mx


def full_client(files=None, crt=None):
    files = files or {}

    def handler(req: httpx.Request):
        if req.url.host == "crt.sh":
            return httpx.Response(200, json=crt or [])
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"Location": f"https://{req.url.host}/"})
        if req.url.path == "/":
            return httpx.Response(200, headers={"Strict-Transport-Security": "max-age=1"}, content=b"<html>hi</html>")
        if req.url.path in files:
            return httpx.Response(200, content=files[req.url.path])
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


GOOD_CERT = lambda host: CertInfo(ok=True, not_after=datetime.now(timezone.utc) + timedelta(days=80),
                                  issuer="R3", tls_version="TLSv1.3")
PUBLIC = lambda host: ["93.184.216.34"]


def test_passive_scan_and_report():
    r = FakeResolver(txt={D: ["v=spf1 include:_spf.google.com ~all"],
                          f"_dmarc.{D}": ["v=DMARC1; p=none; rua=mailto:d@example.ca"],
                          f"google._domainkey.{D}": ["v=DKIM1; k=rsa; p=MIIB"]},
                     mx=[(1, "smtp.google.com")])
    scan = scan_domain(D, secret=SECRET, resolver=r, client=full_client(crt=[{"name_value": "dev.example.ca"}]),
                       cert_fetcher=GOOD_CERT, public_check=PUBLIC)
    assert scan.target_type == "domain" and not scan.domain.active_checks_ran
    rep = build_report(scan)
    assert rep.overall.value == "medium"  # DMARC p=none
    ids = {f.id for f in rep.findings}
    assert "domain-dmarc" in ids and "domain-subdomains-sensitive" in ids
    assert any("ownership verification" in u for u in rep.unverified)
    html = render_html(rep)
    assert "Domain checks passed" in html and "SPF record present" in html


def test_active_scan_requires_ownership():
    with pytest.raises(OwnershipRequired):
        scan_domain(D, secret=SECRET, active=True, resolver=FakeResolver(), client=full_client(),
                    cert_fetcher=GOOD_CERT, public_check=PUBLIC)


def test_active_scan_with_dns_ownership():
    tok = token_for(D, SECRET)
    r = FakeResolver(txt={f"_tracefind.{D}": [f"tracefind-verify={tok}"]})
    scan = scan_domain(D, secret=SECRET, active=True, resolver=r,
                       client=full_client(files={"/.git/config": b"[core]\n\trepositoryformatversion = 0"}),
                       cert_fetcher=GOOD_CERT, public_check=PUBLIC, sleep=lambda s: None)
    assert scan.domain.ownership_verified and scan.domain.active_checks_ran
    assert build_report(scan).overall.value == "high"  # no SPF/DMARC + exposed git


def test_ownership_via_file():
    tok = token_for(D, SECRET)
    scan = scan_domain(D, secret=SECRET, active=True, resolver=FakeResolver(),
                       client=full_client(files={"/.well-known/tracefind-verify.txt": tok.encode()}),
                       cert_fetcher=GOOD_CERT, public_check=PUBLIC, sleep=lambda s: None)
    assert scan.domain.active_checks_ran


def test_private_ip_skips_web_checks():
    def private(host):
        raise DomainError(f"{host} points to a private or reserved address (10.0.0.5); refusing to scan.")
    scan = scan_domain(D, secret=SECRET, resolver=FakeResolver(), client=full_client(),
                       cert_fetcher=GOOD_CERT, public_check=private)
    assert any(c.id == "private-ip" for c in scan.domain.checks)
    assert not any(c.group == "web" and c.id == "cert" for c in scan.domain.checks)


def test_domain_diff():
    base = dict(secret=SECRET, client=None, cert_fetcher=GOOD_CERT, public_check=PUBLIC)
    before = scan_domain(D, resolver=FakeResolver(), **{**base, "client": full_client(crt=[{"name_value": "www.example.ca"}])})
    fixed = FakeResolver(txt={D: ["v=spf1 -all"], f"_dmarc.{D}": ["v=DMARC1; p=reject; rua=mailto:a@b.ca"]})
    after = scan_domain(D, resolver=fixed, **{**base, "client": full_client(
        crt=[{"name_value": "www.example.ca\nstaging.example.ca"}])})
    d = diff_scans(before, after)
    assert "staging.example.ca" in d.new_subdomains
    assert any("SPF" in t for t in d.fixed_problems) and any("DMARC" in t for t in d.fixed_problems)
    assert any("dev, admin or internal" in t for t in d.new_problems)


# ---------------------------------------------------------------- HTTP

def test_http_routes(monkeypatch):
    app = FastAPI()
    app.include_router(domain_router_mod.router)
    monkeypatch.setattr(domain_router_mod, "_secret", lambda: SECRET)
    c = TestClient(app)
    o = c.get("/api/domain/ownership", params={"domain": "https://Example.ca/"}).json()
    assert o["dns"]["name"] == "_tracefind.example.ca" and o["token"] == token_for(D, SECRET)
    assert c.get("/api/domain/ownership", params={"domain": "localhost"}).status_code == 400

    def fake_scan(d, secret, active):
        if active:
            raise OwnershipRequired(d)
        return scan_domain(d, secret=secret, resolver=FakeResolver(), client=full_client(),
                           cert_fetcher=GOOD_CERT, public_check=PUBLIC)
    monkeypatch.setattr(domain_router_mod, "scan_domain", fake_scan)
    import tracefind.history.store as hs
    monkeypatch.setattr(hs, "get_history_store", lambda: hs.HistoryStore(":memory:"))
    import tracefind.history.router as hr
    monkeypatch.setattr(hr, "get_history_store", lambda: hs.HistoryStore(":memory:"))
    r = c.post("/api/domain/scan", json={"domain": D})
    assert r.status_code == 200 and r.json()["report"]["overall"] == "high"
    r = c.post("/api/domain/scan", json={"domain": D, "active": True})
    assert r.status_code == 403 and "ownership" in r.json()["detail"]


def test_nonexistent_domain_and_dns_failure():
    class Missing(FakeResolver):
        def exists(self, name):
            return False
    with pytest.raises(DomainError, match="doesn't exist"):
        scan_domain(D, secret=SECRET, resolver=Missing(), client=full_client(),
                    cert_fetcher=GOOD_CERT, public_check=PUBLIC)

    from tracefind.domain.email_auth import DnsUnavailable

    class Broken(FakeResolver):
        def exists(self, name):
            raise DnsUnavailable("SERVFAIL")
    with pytest.raises(DomainError, match="DNS lookups are failing"):
        scan_domain(D, secret=SECRET, resolver=Broken(), client=full_client(),
                    cert_fetcher=GOOD_CERT, public_check=PUBLIC)

    class FlakyTxt(FakeResolver):
        def exists(self, name):
            return True

        def txt(self, name):
            raise DnsUnavailable("timeout")
    scan = scan_domain(D, secret=SECRET, resolver=FlakyTxt(), client=full_client(),
                       cert_fetcher=GOOD_CERT, public_check=PUBLIC)
    assert not any(c.id in ("spf", "dmarc") for c in scan.domain.checks)  # no false "No SPF"
    assert any(s.status == "error" and s.name.startswith("DNS") for s in scan.sources)
