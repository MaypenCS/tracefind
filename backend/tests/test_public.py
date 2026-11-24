"""Public-site mode (TRACEFIND_PUBLIC=1)."""
import pytest
from fastapi.testclient import TestClient

from tracefind import app as appmod
from tracefind import public
from tracefind.history.store import HistoryStore
from tracefind.public import RateLimiter
from tracefind.report.models import ScanResult


@pytest.fixture
def pub(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACEFIND_PUBLIC", "1")
    monkeypatch.delenv("TRACEFIND_TRUST_CLOUDFLARE", raising=False)
    monkeypatch.setattr(public, "limiter", RateLimiter())
    store = HistoryStore(str(tmp_path / "h.db"))
    import tracefind.history.router as hr
    from tracefind.history.store import get_history_store as original
    appmod.app.dependency_overrides[original] = lambda: store
    monkeypatch.setattr(hr, "get_history_store", lambda: store)
    yield TestClient(appmod.app), store
    appmod.app.dependency_overrides.clear()


def test_local_mode_unchanged(monkeypatch):
    monkeypatch.delenv("TRACEFIND_PUBLIC", raising=False)
    c = TestClient(appmod.app)
    assert c.get("/api/config").json()["public"] is False
    assert c.get("/docs").status_code == 200
    assert "content-security-policy" not in c.get("/api/health").headers


def test_username_sweep_off_and_docs_hidden(pub):
    c, _ = pub
    assert c.get("/api/config").json()["public"] is True
    r = c.get("/api/search/stream", params={"username": "maypen"})
    assert r.status_code == 404 and "public site" in r.json()["detail"]
    assert c.post("/api/search/report", json={"username": "x", "found": []}).status_code == 404
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404


def test_security_headers(pub):
    c, _ = pub
    h = c.get("/api/health").headers
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff" and "max-age" in h["strict-transport-security"]


def test_history_targets_hidden_and_username_history_blocked(pub):
    c, store = pub
    store.save(ScanResult(target="maypencs", target_type="username"))
    assert c.get("/api/history/targets").json() == []
    r = c.get("/api/history", params={"target": "maypencs", "target_type": "username"})
    assert r.status_code == 403


def test_domain_history_needs_ownership(pub, monkeypatch):
    c, store = pub
    import tracefind.history.router as hr
    hr._owner_cache.clear()
    store.save(ScanResult(target="example.ca", target_type="domain"))
    monkeypatch.setattr(hr, "_domain_owner_ok", lambda d: False)
    r = c.get("/api/history", params={"target": "example.ca", "target_type": "domain"})
    assert r.status_code == 403 and "ownership record" in r.json()["detail"]
    monkeypatch.setattr(hr, "_domain_owner_ok", lambda d: True)
    assert len(c.get("/api/history", params={"target": "example.ca", "target_type": "domain"}).json()) == 1


def test_rate_limit_breach(pub, monkeypatch):
    c, _ = pub
    for k in ("HIBP_API_KEY", "DEHASHED_API_KEY", "INTELX_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TRACEFIND_DISABLE_XON", "1")  # endpoint answers 400 fast; limiter still counts
    codes = [c.post("/api/breach", json={"term": "x@y.co"}).status_code for _ in range(11)]
    assert codes[:10] == [400] * 10 and codes[10] == 429
    r = c.post("/api/breach", json={"term": "x@y.co"})
    assert int(r.headers["retry-after"]) > 0
    assert c.get("/api/health").status_code == 200  # other routes unaffected


def test_limiter_window_and_per_ip():
    t = [0.0]
    lim = RateLimiter(rules=[("*", "/api/x", 2, 60)], clock=lambda: t[0])
    assert lim.check("a", "GET", "/api/x") is None and lim.check("a", "GET", "/api/x") is None
    assert lim.check("a", "GET", "/api/x") > 0
    assert lim.check("b", "GET", "/api/x") is None   # separate per IP
    t[0] = 61
    assert lim.check("a", "GET", "/api/x") is None   # window passed
    assert lim.check("a", "GET", "/other") is None    # unmatched path


def test_cloudflare_ip_only_when_trusted(pub, monkeypatch):
    c, _ = pub
    monkeypatch.setattr(public, "limiter", RateLimiter(rules=[("*", "/api/health", 1, 3600)]))
    h1 = {"CF-Connecting-IP": "203.0.113.1"}
    assert c.get("/api/health", headers=h1).status_code == 200
    # Not trusted: header ignored, both requests count as the same test client IP
    assert c.get("/api/health", headers={"CF-Connecting-IP": "203.0.113.2"}).status_code == 429
    monkeypatch.setenv("TRACEFIND_TRUST_CLOUDFLARE", "1")
    monkeypatch.setattr(public, "limiter", RateLimiter(rules=[("*", "/api/health", 1, 3600)]))
    assert c.get("/api/health", headers=h1).status_code == 200
    assert c.get("/api/health", headers={"CF-Connecting-IP": "203.0.113.2"}).status_code == 200
    assert c.get("/api/health", headers=h1).status_code == 429
