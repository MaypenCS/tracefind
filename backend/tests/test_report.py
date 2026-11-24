from datetime import date

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tracefind.report.adapters import from_dehashed, from_hibp, merge_breaches
from tracefind.report.models import Breach, ScanResult, UsernameHit
from tracefind.report.router import router
from tracefind.report.scoring import build_report

app = FastAPI()
app.include_router(router)
client = TestClient(app)


def scan(**kw):
    return ScanResult(target="test@example.com", target_type="email", **kw)


def test_password_breach_is_high():
    r = build_report(scan(breaches=[Breach(name="X", data_classes=["Email addresses", "Passwords"])]))
    assert r.overall.value == "high"
    assert r.findings[0].severity.value == "high"


def test_contact_only_breach_is_low():
    r = build_report(scan(breaches=[Breach(name="X", data_classes=["Email addresses", "Names"])]))
    assert r.overall.value == "low"


def test_sensitive_personal_breach_is_medium():
    r = build_report(scan(breaches=[Breach(name="X", data_classes=["Phone numbers"])]))
    assert r.overall.value == "medium"


def test_username_hits_split_by_sensitivity():
    r = build_report(scan(username_hits=[
        UsernameHit(platform="GitHub", url="u", category="developer"),
        UsernameHit(platform="Tinder", url="u", category="dating"),
    ]))
    sev = {f.id: f.severity.value for f in r.findings}
    assert sev == {"username-sensitive": "medium", "username-mainstream": "low"}


def test_empty_scan_is_info():
    r = build_report(scan())
    assert r.overall.value == "info" and r.findings == []


def test_dehashed_values_never_survive():
    entries = [{"database_name": "LeakDB", "email": ["a@b.com"], "password": ["hunter2"],
                "phone": ["555-0100"]}]
    breaches = from_dehashed(entries)
    dumped = str([b.model_dump() for b in breaches])
    assert "hunter2" not in dumped and "555-0100" not in dumped
    assert "Passwords" in breaches[0].data_classes


def test_merge_same_breach_from_two_sources():
    hibp = from_hibp([{"Title": "LeakDB", "BreachDate": "2020-01-01", "DataClasses": ["Email addresses"]}])
    deh = from_dehashed([{"database_name": "leakdb", "password": ["x"]}])
    merged = merge_breaches(hibp, deh)
    assert len(merged) == 1
    assert set(merged[0].data_classes) == {"Email addresses", "Passwords"}
    assert merged[0].breach_date == date(2020, 1, 1)


def test_html_escapes_target():
    payload = scan().model_dump(mode="json")
    payload["target"] = "<script>alert(1)</script>"
    res = client.post("/api/report/html", json=payload)
    assert res.status_code == 200
    assert "<script>alert(1)</script>" not in res.text
    assert "attachment" in res.headers["content-disposition"]


def test_demo_json_and_html():
    j = client.get("/api/report/demo").json()
    assert j["overall"] == "high" and j["scan"]["is_demo"]
    h = client.get("/api/report/demo?format=html")
    assert "DEMO REPORT" in h.text


def test_demo_pdf():
    res = client.get("/api/report/demo?format=pdf")
    assert res.status_code in (200, 501)
    if res.status_code == 200:
        assert res.content[:4] == b"%PDF"


def test_keyword_matching_is_whole_word():
    r = build_report(scan(breaches=[Breach(name="X", data_classes=["Email addresses", "Business names", "Spoken languages"])]))
    assert r.overall.value == "low"
    r = build_report(scan(breaches=[Breach(name="X", data_classes=["Physical addresses"])]))
    assert r.overall.value == "medium"
    r = build_report(scan(breaches=[Breach(name="X", data_classes=["Password hints"])]))
    assert r.overall.value == "high"
