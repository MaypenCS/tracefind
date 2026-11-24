"""XposedOrNot provider, HIBP free catalogue, Pwned Passwords proxy."""
import asyncio
import hashlib
from datetime import date, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from tracefind import breach, hibp_catalog
from tracefind.domain.breached_service import check_breached_service
from tracefind.hibp_catalog import Catalog, enrich
from tracefind.integration import scan_from_breach_results
from tracefind.report.scoring import build_report

RECENT = (date.today() - timedelta(days=200)).isoformat()
CATALOG = [
    {"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com", "BreachDate": "2012-05-05",
     "PwnCount": 164611595, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True},
    {"Name": "LinkedInScrape", "Title": "LinkedIn Scraped Data (2021)", "Domain": "linkedin.com",
     "BreachDate": "2021-04-08", "PwnCount": 125698496,
     "DataClasses": ["Email addresses", "Names", "Phone numbers"], "IsVerified": True},
    {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
     "PwnCount": 152445165, "DataClasses": ["Email addresses", "Password hints", "Passwords"], "IsVerified": True},
    {"Name": "ShopCo", "Title": "ShopCo", "Domain": "shop.example.ca", "BreachDate": RECENT,
     "PwnCount": 1200, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True},
]
XON_BODY = {"ExposedBreaches": {"breaches_details": [
    {"breach": "LinkedIn2021", "domain": "linkedin.com", "xposed_data": "Email addresses;Names",
     "xposed_records": 125698496, "xposed_date": "2021", "password_risk": "unknown", "verified": "Yes"},
    {"breach": "Adobe", "domain": "adobe.com", "xposed_data": "Email addresses;Usernames",
     "xposed_records": 152445165, "xposed_date": "2013", "password_risk": "hardtocrack", "verified": "Yes"},
    {"breach": "ObscureForum", "domain": "", "xposed_data": "Email addresses;IP addresses",
     "xposed_records": 5000, "xposed_date": "2019", "password_risk": "", "verified": "No"},
]}, "PastesSummary": {"cnt": 2}}


def handler(req: httpx.Request):
    if req.url.host == "api.xposedornot.com":
        email = req.url.params.get("email")
        if email == "clean@example.com":
            return httpx.Response(404, json={"Error": "Not found"})
        if email == "busy@example.com":
            return httpx.Response(429, headers={"Retry-After": "120"})
        return httpx.Response(200, json=XON_BODY)
    if req.url.host == "haveibeenpwned.com" and req.url.path == "/api/v3/breaches":
        assert req.headers.get("user-agent")
        return httpx.Response(200, json=CATALOG * 30)  # >100 entries so it gets cached
    return httpx.Response(500)


@pytest.fixture(autouse=True)
def only_xon(monkeypatch, tmp_path):
    monkeypatch.delenv("TRACEFIND_DISABLE_XON", raising=False)
    for k in ("HIBP_API_KEY", "DEHASHED_API_KEY", "INTELX_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(hibp_catalog, "CACHE", tmp_path / "hibp.json")


def run(term, **kw):
    return asyncio.run(breach.lookup(term, transport=httpx.MockTransport(handler), **kw))


# ---------------------------------------------------------------- XposedOrNot

def test_xon_on_by_default_and_skips_usernames():
    assert breach.configured()["xposedornot"] is True
    out = run("justauser")
    assert out == [{"provider": "xposedornot", "skipped": "XposedOrNot searches email addresses only"}]


def test_xon_parses_and_enriches_from_catalogue():
    [xon] = run("me@example.com")
    names = [b["name"] for b in xon["breaches"]]
    assert names == ["LinkedIn Scraped Data (2021)", "ObscureForum", "Adobe"]  # newest first, HIBP titles
    li = xon["breaches"][0]
    assert li["date"] == "2021-04-08" and "Phone numbers" in li["data_types"]  # exact date + merged classes
    adobe = xon["breaches"][2]
    assert adobe["secrets_exposed"] and "Passwords" in adobe["data_types"]
    obscure = xon["breaches"][1]
    assert obscure["date"] == "2019" and obscure["verified"] is False  # unmatched: kept as reported
    assert xon["pastes"] == 2 and "CC BY 4.0" in xon["attribution"]


def test_xon_not_found_and_rate_limited():
    assert run("clean@example.com")[0] == {"provider": "xposedornot", "count": 0, "breaches": []}
    err = run("busy@example.com")[0]["error"]
    assert "limit" in err and "120s" in err


def test_xon_works_offline_without_catalogue(monkeypatch):
    def no_hibp(req):
        return httpx.Response(503) if req.url.host == "haveibeenpwned.com" else handler(req)
    [xon] = asyncio.run(breach.lookup("me@example.com", transport=httpx.MockTransport(no_hibp)))
    assert xon["count"] == 3 and "attribution" not in xon
    assert xon["breaches"][0]["name"] == "LinkedIn2021"


def test_xon_results_become_report():
    out = run("me@example.com")
    scan = scan_from_breach_results("me@example.com", out)
    rep = build_report(scan)
    assert rep.overall.value == "high"  # Adobe: passwords (hardtocrack)
    assert {b.name for b in scan.breaches} == {"LinkedIn Scraped Data (2021)", "ObscureForum", "Adobe"}
    assert any(p.title.startswith("2 paste") for p in scan.pastes)
    assert scan.sources[0].name == "XposedOrNot" and "CC BY" in scan.sources[0].detail


def test_same_breach_from_xon_and_hibp_is_merged(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")

    def both(req):
        if req.url.path.startswith("/api/v3/breachedaccount"):
            return httpx.Response(200, json=[{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04",
                                              "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True}])
        return handler(req)
    out = asyncio.run(breach.lookup("me@example.com", transport=httpx.MockTransport(both)))
    scan = scan_from_breach_results("me@example.com", out)
    adobe = [b for b in scan.breaches if b.name == "Adobe"]
    assert len(adobe) == 1 and "XposedOrNot" in adobe[0].source and "HaveIBeenPwned" in adobe[0].source


# ---------------------------------------------------------------- catalogue

def test_catalogue_matching():
    cat = Catalog(CATALOG)
    assert cat.match("LinkedIn2021")["Name"] == "LinkedInScrape"
    assert cat.match("linkedin")["Name"] == "LinkedIn"
    assert cat.match("Adobe-2013")["Name"] == "Adobe"
    assert cat.match("Whatever", "linkedin.com", "2012")["Name"] == "LinkedIn"
    assert cat.match("Whatever", "linkedin.com") is None  # ambiguous without a year
    assert cat.match("NoSuchBreach") is None
    e = enrich({"name": "nosuch", "data_types": ["Names"]}, cat)
    assert e == {"name": "nosuch", "data_types": ["Names"]}


def test_catalogue_cache_and_offline_fallback(tmp_path):
    c = httpx.Client(transport=httpx.MockTransport(handler))
    assert len(hibp_catalog.load_catalog(c)) == len(CATALOG) * 30
    assert hibp_catalog.CACHE.exists()
    offline = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    assert hibp_catalog.load_catalog(offline, max_age=0) is not None  # stale copy used
    hibp_catalog.CACHE.unlink()
    assert hibp_catalog.load_catalog(offline) is None


def test_domain_breached_service_check():
    cat = Catalog(CATALOG)
    [c] = check_breached_service("example.ca", cat)  # matches shop.example.ca, recent + passwords
    assert c.status == "fail" and c.severity.value == "high" and "ShopCo" in c.evidence[0]
    [c] = check_breached_service("linkedin.com", cat)
    assert c.severity.value == "medium" and "2 known breaches" in c.title
    [c] = check_breached_service("maypen-test.ca", cat)
    assert c.status == "pass"
    [c] = check_breached_service("x.ca", None)
    assert c.status == "info"


# ---------------------------------------------------------------- Pwned Passwords proxy

def test_password_range_proxy(monkeypatch):
    from tracefind import app as appmod
    sha = hashlib.sha1(b"password123").hexdigest().upper()
    seen = {}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, url, headers=None):
            seen["url"], seen["headers"] = url, headers
            return httpx.Response(200, text=f"{sha[5:]}:2254650\r\n0000000000000000000000000000000000A:0",
                                  request=httpx.Request("GET", url))
    monkeypatch.setattr(appmod.httpx, "AsyncClient", FakeClient)
    c = TestClient(appmod.app)
    r = c.get(f"/api/password/range/{sha[:5]}")
    assert r.status_code == 200 and f"{sha[5:]}:2254650" in r.text
    assert seen["url"].endswith("/" + sha[:5]) and seen["headers"]["Add-Padding"] == "true"
    assert sha not in seen["url"]  # only the prefix leaves
    assert c.get("/api/password/range/xyz12").status_code == 400
    assert c.get(f"/api/password/range/{sha[:6]}").status_code == 400
