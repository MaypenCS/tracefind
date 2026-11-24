from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tracefind.history.router import router, save_and_report
from tracefind.history.store import HistoryStore, get_history_store
from tracefind.report.diff import diff_scans
from tracefind.report.models import Breach, ScanResult, SourceStatus, UsernameHit
from tracefind.report.render import render_html
from tracefind.report.scoring import build_report
from tracefind.verify.config import VerifyConfig
from tracefind.verify.mailer import ConsoleMailer
from tracefind.verify.router import get_verification_service
from tracefind.verify.service import VerificationService

T0 = datetime(2026, 10, 23, 15, 0, tzinfo=timezone.utc)
HIBP_OK = SourceStatus(name="HaveIBeenPwned", status="ok")


def hit(p, c="social"):
    return UsernameHit(platform=p, url=f"https://{p.lower()}.example/u", category=c)


def mk(target="maypencs", ttype="username", when=T0, hits=(), breaches=(), sources=()):
    return ScanResult(target=target, target_type=ttype, scanned_at=when,
                      username_hits=list(hits), breaches=list(breaches), sources=list(sources))


@pytest.fixture
def store(tmp_path):
    return HistoryStore(str(tmp_path / "h.db"))


# ---- diff ---------------------------------------------------------------

def test_diff_accounts_and_breaches():
    a = mk(hits=[hit("GitHub"), hit("Reddit")],
           breaches=[Breach(name="X", data_classes=["Email addresses"])], sources=[HIBP_OK])
    b = mk(when=T0 + timedelta(days=30), hits=[hit("GitHub"), hit("Tinder", "dating")],
           breaches=[Breach(name="X", data_classes=["Email addresses", "Passwords"]),
                     Breach(name="Y", data_classes=["Names"])], sources=[HIBP_OK])
    d = diff_scans(a, b)
    assert [h.platform for h in d.new_accounts] == ["Tinder"]
    assert [h.platform for h in d.removed_accounts] == ["Reddit"]
    assert [x.name for x in d.new_breaches] == ["Y"]
    assert d.expanded_breaches[0].new_data_classes == ["Passwords"]
    assert d.has_changes


def test_diff_ignores_breaches_when_previous_had_no_breach_checks():
    a = mk()  # unverified / username-only scan
    b = mk(when=T0 + timedelta(days=1), breaches=[Breach(name="Y")], sources=[HIBP_OK])
    d = diff_scans(a, b)
    assert d.new_breaches == [] and d.breach_coverage_changed


def test_no_changes_summary():
    a = mk(hits=[hit("GitHub")])
    d = diff_scans(a, mk(when=T0 + timedelta(days=1), hits=[hit("github")]))
    assert not d.has_changes and d.summary() == ["No changes since the previous scan"]


# ---- report integration --------------------------------------------------

def test_report_flags_new_accounts_and_breaches():
    a = mk(hits=[hit("GitHub")], sources=[HIBP_OK])
    b = mk(when=T0 + timedelta(days=30), hits=[hit("GitHub"), hit("Coinbase", "crypto")],
           breaches=[Breach(name="Y", data_classes=["Passwords"], breach_date=date(2026, 11, 1))],
           sources=[HIBP_OK])
    r = build_report(b, previous=a)
    titles = [f.title for f in r.findings]
    assert any(t.startswith("NEW: Password data exposed in the Y breach") for t in titles)
    new_acc = next(f for f in r.findings if f.id == "new-accounts")
    assert new_acc.severity.value == "medium"  # crypto is a sensitive category
    html = render_html(r)
    assert "Changes since October 23, 2026" in html and "Coinbase" in html


def test_report_without_previous_has_no_changes():
    r = build_report(mk(hits=[hit("GitHub")]))
    assert r.changes is None and r.changes_summary == []


# ---- store ----------------------------------------------------------------

def test_save_list_previous(store):
    id1 = store.save(mk(hits=[hit("GitHub")]))
    id2 = store.save(mk(target="MaypenCS", when=T0 + timedelta(days=7), hits=[hit("GitHub"), hit("X")]))
    scans = store.list_scans("maypencs", "username")
    assert [s.id for s in scans] == [id2, id1]
    assert scans[0].username_hits == 2
    prev_id, prev = store.previous(store.get(id2)[1], before_id=id2)
    assert prev_id == id1
    assert store.list_targets()[0]["scans"] == 2


def test_retention(tmp_path):
    s = HistoryStore(str(tmp_path / "r.db"), max_per_target=3)
    for i in range(5):
        s.save(mk(when=T0 + timedelta(days=i)))
    assert len(s.list_scans("maypencs", "username")) == 3


def test_demo_not_saved(store):
    scan = mk()
    scan.is_demo = True
    with pytest.raises(ValueError):
        store.save(scan)


def test_save_and_report_helper(store):
    store.save(mk(hits=[hit("GitHub")]))
    out = save_and_report(mk(when=T0 + timedelta(days=30), hits=[hit("GitHub"), hit("Twitch", "gaming")]), store)
    assert out["report"].changes.new_accounts[0].platform == "Twitch"


# ---- HTTP + email gating -------------------------------------------------

@pytest.fixture
def client(store, tmp_path):
    mailer = ConsoleMailer()
    svc = VerificationService(VerifyConfig(secret=b"s", db_path=str(tmp_path / "v.db")), mailer)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_history_store] = lambda: store
    get_verification_service.cache_clear()
    import tracefind.verify.router as vr
    orig = vr.get_verification_service
    vr.get_verification_service = lambda: svc  # history router looks this up lazily
    yield TestClient(app), svc, mailer
    vr.get_verification_service = orig


def test_http_username_history(client, store):
    c, _, _ = client
    id1 = store.save(mk(hits=[hit("GitHub")]))
    id2 = store.save(mk(when=T0 + timedelta(days=5), hits=[hit("GitHub"), hit("Kick")]))
    assert len(c.get("/api/history", params={"target": "maypencs", "target_type": "username"}).json()) == 2
    cmp = c.get("/api/history/compare", params={"from_id": id2, "to_id": id1}).json()  # order-insensitive
    assert cmp["new_accounts"][0]["platform"] == "Kick" and cmp["has_changes"]
    rep = c.get(f"/api/history/scan/{id2}/report").json()
    assert rep["changes"]["previous_id"] == id1
    assert "Changes since" in c.get(f"/api/history/scan/{id2}/report?format=html").text
    assert c.delete(f"/api/history/scan/{id1}").json() == {"deleted": 1}
    assert c.get("/api/history/scan/999").status_code == 404


def test_http_email_history_requires_verification(client, store):
    c, svc, mailer = client
    sid = store.save(mk(target="me@example.com", ttype="email",
                        breaches=[Breach(name="X", data_classes=["Passwords"])], sources=[HIBP_OK]))
    params = {"target": "me@example.com", "target_type": "email"}
    assert c.get("/api/history", params=params).status_code == 403
    assert c.get(f"/api/history/scan/{sid}").status_code == 403
    assert c.delete(f"/api/history/scan/{sid}").status_code == 403

    svc.request_code("me@example.com")
    tok = svc.confirm_code("me@example.com", mailer.sent[-1][1]).token
    h = {"X-TraceFind-Verify": tok}
    assert len(c.get("/api/history", params=params, headers=h).json()) == 1
    assert c.get(f"/api/history/scan/{sid}", headers=h).json()["breaches"][0]["name"] == "X"


def test_compare_rejects_different_targets(client, store):
    c, _, _ = client
    a = store.save(mk(target="one"))
    b = store.save(mk(target="two"))
    assert c.get("/api/history/compare", params={"from_id": a, "to_id": b}).status_code == 400


def test_retention_deletes_old_scans(tmp_path):
    from datetime import datetime, timedelta, timezone
    s = HistoryStore(str(tmp_path / "ret.db"), max_age_days=90)
    now = datetime.now(timezone.utc)
    s.save(mk(when=now - timedelta(days=200)))
    s.save(mk(when=now - timedelta(days=10)))
    assert len(s.list_scans("maypencs", "username")) == 1


def test_retention_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACEFIND_HISTORY_DAYS", "30")
    assert HistoryStore(str(tmp_path / "e.db")).max_age_days == 30
