"""Settings for email verification. All values come from environment variables."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _secret() -> bytes:
    """Signing secret. Set TRACEFIND_SECRET in production; otherwise one is generated
    once and saved to .tracefind_secret so tokens survive restarts."""
    env = os.getenv("TRACEFIND_SECRET")
    if env:
        return env.encode()
    path = Path(os.getenv("TRACEFIND_SECRET_FILE", ".tracefind_secret"))
    if path.exists():
        return path.read_bytes().strip()
    value = secrets.token_hex(32).encode()
    path.write_bytes(value)
    return value


@dataclass
class VerifyConfig:
    secret: bytes = field(default_factory=_secret)
    db_path: str = field(default_factory=lambda: os.getenv("TRACEFIND_DB", "tracefind_verify.db"))

    code_ttl_s: int = 10 * 60          # code valid for 10 minutes
    max_attempts: int = 5              # wrong guesses before the code is burned
    resend_cooldown_s: int = 60        # one code per email per minute
    max_codes_per_email_hour: int = 5
    max_codes_per_ip_hour: int = 15
    token_ttl_s: int = 24 * 60 * 60    # verified for 24 hours

    smtp_host: str | None = field(default_factory=lambda: os.getenv("SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "587")))
    smtp_user: str | None = field(default_factory=lambda: os.getenv("SMTP_USER"))
    smtp_password: str | None = field(default_factory=lambda: os.getenv("SMTP_PASSWORD"))
    # Set SMTP_FROM to an address on your brand domain, e.g. "TraceFind <no-reply@yourbrand.ca>".
    smtp_from: str = field(default_factory=lambda: os.getenv("SMTP_FROM", "TraceFind <no-reply@localhost>"))
    smtp_ssl: bool = field(default_factory=lambda: os.getenv("SMTP_SSL", "0") == "1")  # port 465 style
