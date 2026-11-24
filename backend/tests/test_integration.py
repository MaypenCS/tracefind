"""Tests for the wiring between tracefind's scanners and the report/verify/history modules."""
import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from tracefind import app as appmod
from tracefind import breach
from tracefind.history.store import HistoryStore
from tracefind.integration import scan_from_breach_results, scan_from_username_results
from tracefind.verify.config import VerifyConfig
from tracefind.verify.mailer import ConsoleMailer
from tracefind.verify.service import VerificationService

from test_tracefind import breach_handler


@pytest.fixture
def env(monkeypatch, tmp_path):
    store = HistoryStore(str(tmp_path / "h.db"))
    mailer = ConsoleMailer()
    svc = VerificationService(VerifyConfig(secret=b"t", db_path=str(tmp_path / "v.db")), mailer)
    import tracefind.history.router as hr
    monkeypatch.setattr(hr, "get_history_store", lambda: store)
    monkeypatch.setattr(appmod, "get_verification_service", lambda: svc)
    monkeypatch.setenv("HIBP_API_KEY", "k")
    monkeypatch.setenv("DEHASHED_API_KEY", "k")
    monkeypatch.delenv("INTELX_API_KEY", raising=False)
    monkeypatch.setenv("TRACEFIND_DISABLE_XON", "1")
    real = breach.lookup
    monkeypatch.setattr(breach, "lookup",
                        lambda term, providers=None: real(term, providers, transport=httpx.MockTransport(breach_handler)))
    return TestClient(appmod.app), store, svc, mailer


def test_username_scan_from_results_categorizes():
    s = scan_from_username_results("maypen", [{"site": "GitHub", "url": "u1"}, {"site": "Tinder", "url": "u2"}], 400)
    cats = {h.platform: h.category for h in s.username_hits}
    assert cats == {"GitHub": "developer", "Tinder": "dating"} and s.sites_checked == 400


def test_breach_conversion_merges_and_never_leaks():
    out = asyncio.run(_lookup("me@maypen.ca"))
    s = scan_from_breach_results("me@maypen.ca", out)
    names = {b.name: b for b in s.breaches}
    assert set(names) == {"NewSite", "OldSite", "LeakA", "LeakB"}
    assert "Passwords" in names["LeakA"].data_classes and "hunter2" not in s.model_dump_json()
    assert s.target_type == "email" and all(x.status == "ok" for x in s.sources)


def _lookup(term):
    import os
    os.environ["HIBP_API_KEY"] = os.environ["DEHASHED_API_KEY"] = "k"
    os.environ.pop("INTELX_API_KEY", None)
    os.environ["TRACEFIND_DISABLE_XON"] = "1"
    return breach.lookup(term, transport=httpx.MockTransport(breach_handler))


def test_username_report_endpoint_saves_history_and_shows_changes(env):
    c, store, _, _ = env
    r1 = c.post("/api/search/report", json={"username": "maypen", "checked": 400,
                                             "found": [{"site": "GitHub", "url": "https://github.com/maypen"}]}).json()
    assert r1["scan_id"] and r1["report"]["changes"] is None
    r2 = c.post("/api/search/report", json={"username": "maypen", "checked": 400, "found": [
        {"site": "GitHub", "url": "https://github.com/maypen"}, {"site": "Coinbase", "url": "x"}]}).json()
    assert r2["report"]["changes"]["new_accounts"][0]["platform"] == "Coinbase"
    assert len(store.list_scans("maypen", "username")) == 2
    assert c.post("/api/search/report", json={"username": "bad name"}).status_code == 400


def test_email_breach_requires_verification(env):
    c, store, svc, mailer = env
    r = c.post("/api/breach", json={"term": "me@maypen.ca"})
    assert r.status_code == 403 and r.json()["detail"]["verify_required"]

    svc.request_code("me@maypen.ca")
    tok = svc.confirm_code("me@maypen.ca", mailer.sent[-1][1]).token
    r = c.post("/api/breach", json={"term": "me@maypen.ca"}, headers={"X-TraceFind-Verify": tok})
    assert r.status_code == 200
    j = r.json()
    assert j["report"]["overall"] == "high" and j["scan_id"]
    assert len(j["results"]) == 2  # original provider output still returned for the existing UI
    assert len(store.list_scans("me@maypen.ca", "email")) == 1

    other = c.post("/api/breach", json={"term": "someone@else.ca"}, headers={"X-TraceFind-Verify": tok})
    assert other.status_code == 403  # token only unlocks its own address


def test_username_breach_not_gated_or_saved(env, monkeypatch):
    c, store, _, _ = env
    monkeypatch.delenv("DEHASHED_API_KEY")  # shared mock only answers the email query
    r = c.post("/api/breach", json={"term": "justauser"}).json()
    assert r["scan_id"] is None and "report" in r
    assert store.list_targets() == []


def test_new_routes_not_shadowed_by_ui():
    c = TestClient(appmod.app)
    assert c.get("/api/report/demo").json()["scan"]["is_demo"]
    assert c.get("/api/domain/ownership", params={"domain": "example.ca"}).json()["dns"]["type"] == "TXT"
