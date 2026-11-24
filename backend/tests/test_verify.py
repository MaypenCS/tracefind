import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tracefind.report.models import Breach, ScanResult, SourceStatus, UsernameHit
from tracefind.verify.config import VerifyConfig
from tracefind.verify.mailer import ConsoleMailer
from tracefind.verify.router import VERIFY_HEADER, gate_scan, get_verification_service, router
from tracefind.verify.service import VerificationService, VerifyError


class Clock:
    def __init__(self):
        self.t = 1_800_000_000

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    clock, mailer = Clock(), ConsoleMailer()
    cfg = VerifyConfig(secret=b"test-secret", db_path=str(tmp_path / "v.db"))
    return VerificationService(cfg, mailer, clock), mailer, clock


def last_code(mailer):
    return mailer.sent[-1][1]


def test_happy_path(env):
    svc, mailer, _ = env
    svc.request_code("Romaine@Example.com", "1.1.1.1")
    tok = svc.confirm_code("romaine@example.com", last_code(mailer))
    assert svc.is_verified("ROMAINE@example.com", tok.token)


def test_code_is_single_use(env):
    svc, mailer, _ = env
    svc.request_code("a@example.com")
    code = last_code(mailer)
    svc.confirm_code("a@example.com", code)
    with pytest.raises(VerifyError):
        svc.confirm_code("a@example.com", code)


def test_token_bound_to_email(env):
    svc, mailer, _ = env
    svc.request_code("a@example.com")
    tok = svc.confirm_code("a@example.com", last_code(mailer)).token
    assert not svc.is_verified("b@example.com", tok)


def test_tampered_token_rejected(env):
    svc, mailer, _ = env
    svc.request_code("a@example.com")
    tok = svc.confirm_code("a@example.com", last_code(mailer)).token
    payload, sig = tok.split(".")
    assert not svc.is_verified("a@example.com", payload + "." + sig[:-2] + "AA")
    assert not svc.is_verified("a@example.com", "garbage")
    assert not svc.is_verified("a@example.com", None)


def test_token_expires(env):
    svc, mailer, clock = env
    svc.request_code("a@example.com")
    tok = svc.confirm_code("a@example.com", last_code(mailer)).token
    clock.t += 24 * 3600 + 1
    assert not svc.is_verified("a@example.com", tok)


def test_code_expires(env):
    svc, mailer, clock = env
    svc.request_code("a@example.com")
    clock.t += 10 * 60 + 1
    with pytest.raises(VerifyError, match="expired"):
        svc.confirm_code("a@example.com", last_code(mailer))


def test_lockout_after_wrong_attempts(env):
    svc, mailer, _ = env
    svc.request_code("a@example.com")
    good = last_code(mailer)
    bad = "000000" if good != "000000" else "111111"
    for _ in range(5):
        with pytest.raises(VerifyError):
            svc.confirm_code("a@example.com", bad)
    with pytest.raises(VerifyError, match="Too many"):
        svc.confirm_code("a@example.com", good)  # even the right code is refused now


def test_resend_cooldown_and_hourly_limit(env):
    svc, _, clock = env
    svc.request_code("a@example.com")
    with pytest.raises(VerifyError) as e:
        svc.request_code("a@example.com")
    assert e.value.status == 429
    for _ in range(4):
        clock.t += 61
        svc.request_code("a@example.com")
    clock.t += 61
    with pytest.raises(VerifyError, match="Too many codes"):
        svc.request_code("a@example.com")


def test_ip_limit(env):
    svc, _, _ = env
    for i in range(15):
        svc.request_code(f"u{i}@example.com", "9.9.9.9")
    with pytest.raises(VerifyError, match="network"):
        svc.request_code("other@example.com", "9.9.9.9")


def test_nothing_stored_in_plaintext(env, tmp_path):
    svc, mailer, _ = env
    svc.request_code("secret.person@example.com")
    code = last_code(mailer)
    raw = (tmp_path / "v.db").read_bytes()
    assert b"secret.person" not in raw and code.encode() not in raw


def test_invalid_email(env):
    svc, _, _ = env
    with pytest.raises(VerifyError):
        svc.request_code("not-an-email")


def test_failed_send_clears_code(env):
    svc, _, _ = env

    class Broken:
        def send_code(self, *a):
            raise OSError("smtp down")

    svc.mailer = Broken()
    with pytest.raises(VerifyError) as e:
        svc.request_code("a@example.com")
    assert e.value.status == 502
    with pytest.raises(VerifyError, match="No active code"):
        svc.confirm_code("a@example.com", "123456")


def test_gate_scan():
    scan = ScanResult(target="a@example.com", target_type="email",
                      username_hits=[UsernameHit(platform="GitHub", url="u", category="developer")],
                      breaches=[Breach(name="X", data_classes=["Passwords"])],
                      sources=[SourceStatus(name="HaveIBeenPwned", status="ok")])
    gated = gate_scan(scan, verified=False)
    assert gated.breaches == [] and len(gated.username_hits) == 1
    assert any(s.status == "skipped" for s in gated.sources)
    assert scan.breaches, "original must not be mutated"
    assert gate_scan(scan, verified=True).breaches


def test_http_flow(env):
    svc, mailer, _ = env
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_verification_service] = lambda: svc
    c = TestClient(app)

    assert c.post("/api/verify/request", json={"email": "a@example.com"}).json() == {"sent": True}
    r = c.post("/api/verify/request", json={"email": "a@example.com"})
    assert r.status_code == 429 and "retry-after" in r.headers
    assert c.post("/api/verify/confirm", json={"email": "a@example.com", "code": "x"}).status_code == 400
    tok = c.post("/api/verify/confirm", json={"email": "a@example.com", "code": last_code(mailer)}).json()["token"]
    s = c.post("/api/verify/status", json={"email": "a@example.com"}, headers={VERIFY_HEADER: tok})
    assert s.json() == {"verified": True}
