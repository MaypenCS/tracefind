"""Email ownership verification: one-time codes plus short-lived signed tokens.

Flow:
  1. request_code(email, ip)  -> emails a 6-digit code (stored only as an HMAC)
  2. confirm_code(email, code) -> returns a signed token valid for 24h
  3. is_verified(email, token) -> True only for that exact email, until expiry

Emails and codes are never stored in plain text. The DB holds HMACs only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

from .config import VerifyConfig
from .mailer import Mailer, default_mailer

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


class VerifyError(Exception):
    def __init__(self, message: str, status: int = 400, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


@dataclass
class TokenInfo:
    token: str
    expires_at: int


def normalize_email(email: str) -> str:
    e = (email or "").strip().lower()
    if len(e) > 254 or not EMAIL_RE.match(e):
        raise VerifyError("Enter a valid email address.")
    return e


class VerificationService:
    def __init__(self, cfg: VerifyConfig | None = None, mailer: Mailer | None = None, clock=time.time):
        self.cfg = cfg or VerifyConfig()
        self.mailer = mailer or default_mailer(self.cfg)
        self.clock = clock
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.cfg.db_path, check_same_thread=False)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS verify_codes (
                email_h   TEXT PRIMARY KEY,
                code_h    TEXT NOT NULL,
                expires   INTEGER NOT NULL,
                attempts  INTEGER NOT NULL DEFAULT 0,
                sent_at   INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verify_sends (
                key   TEXT NOT NULL,     -- 'e:<email_h>' or 'ip:<ip_h>'
                ts    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_sends ON verify_sends(key, ts);
        """)
        self._db.commit()

    # ---- helpers -------------------------------------------------------
    def _h(self, purpose: str, value: str) -> str:
        return hmac.new(self.cfg.secret, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()

    def _now(self) -> int:
        return int(self.clock())

    def _count_since(self, key: str, since: int) -> int:
        return self._db.execute("SELECT COUNT(*) FROM verify_sends WHERE key=? AND ts>=?",
                                (key, since)).fetchone()[0]

    # ---- step 1 ---------------------------------------------------------
    def request_code(self, email: str, ip: str = "unknown") -> None:
        email = normalize_email(email)
        eh, iph = self._h("email", email), self._h("ip", ip)
        now = self._now()
        with self._lock:
            row = self._db.execute("SELECT sent_at FROM verify_codes WHERE email_h=?", (eh,)).fetchone()
            if row and now - row[0] < self.cfg.resend_cooldown_s:
                wait = self.cfg.resend_cooldown_s - (now - row[0])
                raise VerifyError(f"Please wait {wait}s before requesting another code.", 429, wait)
            hour_ago = now - 3600
            if self._count_since(f"e:{eh}", hour_ago) >= self.cfg.max_codes_per_email_hour:
                raise VerifyError("Too many codes requested for this address. Try again later.", 429, 3600)
            if self._count_since(f"ip:{iph}", hour_ago) >= self.cfg.max_codes_per_ip_hour:
                raise VerifyError("Too many requests from your network. Try again later.", 429, 3600)

            code = f"{secrets.randbelow(10**6):06d}"
            self._db.execute(
                "INSERT INTO verify_codes(email_h, code_h, expires, attempts, sent_at) VALUES(?,?,?,0,?) "
                "ON CONFLICT(email_h) DO UPDATE SET code_h=excluded.code_h, expires=excluded.expires, "
                "attempts=0, sent_at=excluded.sent_at",
                (eh, self._h("code", f"{eh}:{code}"), now + self.cfg.code_ttl_s, now))
            self._db.executemany("INSERT INTO verify_sends(key, ts) VALUES(?,?)",
                                 [(f"e:{eh}", now), (f"ip:{iph}", now)])
            self._db.execute("DELETE FROM verify_sends WHERE ts < ?", (now - 2 * 3600,))
            self._db.commit()

        try:
            self.mailer.send_code(email, code, self.cfg.code_ttl_s // 60)
        except Exception as e:  # don't leave a code that was never delivered
            with self._lock:
                self._db.execute("DELETE FROM verify_codes WHERE email_h=?", (eh,))
                self._db.commit()
            raise VerifyError("Couldn't send the verification email. Try again shortly.", 502) from e

    # ---- step 2 ---------------------------------------------------------
    def confirm_code(self, email: str, code: str) -> TokenInfo:
        email = normalize_email(email)
        code = re.sub(r"\D", "", code or "")
        eh = self._h("email", email)
        now = self._now()
        with self._lock:
            row = self._db.execute("SELECT code_h, expires, attempts FROM verify_codes WHERE email_h=?",
                                   (eh,)).fetchone()
            if not row:
                raise VerifyError("No active code for this address. Request a new one.")
            code_h, expires, attempts = row
            if now > expires:
                self._db.execute("DELETE FROM verify_codes WHERE email_h=?", (eh,))
                self._db.commit()
                raise VerifyError("That code has expired. Request a new one.")
            if attempts >= self.cfg.max_attempts:
                raise VerifyError("Too many wrong attempts. Request a new code.", 429)
            if len(code) != 6 or not hmac.compare_digest(code_h, self._h("code", f"{eh}:{code}")):
                self._db.execute("UPDATE verify_codes SET attempts=attempts+1 WHERE email_h=?", (eh,))
                self._db.commit()
                left = self.cfg.max_attempts - attempts - 1
                raise VerifyError(f"Incorrect code. {left} attempt{'s' if left != 1 else ''} left."
                                  if left > 0 else "Too many wrong attempts. Request a new code.",
                                  400 if left > 0 else 429)
            self._db.execute("DELETE FROM verify_codes WHERE email_h=?", (eh,))  # single use
            self._db.commit()
        return self._issue_token(eh, now)

    # ---- tokens ---------------------------------------------------------
    def _issue_token(self, email_h: str, now: int) -> TokenInfo:
        exp = now + self.cfg.token_ttl_s
        payload = base64.urlsafe_b64encode(json.dumps({"e": email_h, "x": exp}).encode()).rstrip(b"=")
        sig = base64.urlsafe_b64encode(
            hmac.new(self.cfg.secret, b"tok:" + payload, hashlib.sha256).digest()).rstrip(b"=")
        return TokenInfo(token=f"{payload.decode()}.{sig.decode()}", expires_at=exp)

    def is_verified(self, email: str, token: str | None) -> bool:
        if not token or "." not in token:
            return False
        try:
            email = normalize_email(email)
            payload, sig = token.split(".", 1)
            expected = base64.urlsafe_b64encode(
                hmac.new(self.cfg.secret, b"tok:" + payload.encode(), hashlib.sha256).digest()).rstrip(b"=")
            if not hmac.compare_digest(expected.decode(), sig):
                return False
            data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            return (hmac.compare_digest(data["e"], self._h("email", email))
                    and self._now() < int(data["x"]))
        except Exception:
            return False
