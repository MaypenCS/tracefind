"""Sends the verification code. Uses SMTP when configured; otherwise prints the code
to the server console (dev mode), so you can test without an email account."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Protocol

from tracefind.report.brand import brand_line, brand_name

from .config import VerifyConfig

log = logging.getLogger("tracefind.verify")


class Mailer(Protocol):
    def send_code(self, to: str, code: str, ttl_minutes: int) -> None: ...


def _message(cfg: VerifyConfig, to: str, code: str, ttl: int) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"Your TraceFind verification code: {code}"
    msg["From"] = cfg.smtp_from
    msg["To"] = to
    msg.set_content(
        f"Your TraceFind verification code is: {code}\n\n"
        f"It expires in {ttl} minutes.\n\n"
        "Someone asked to check this email address for data-breach exposure. If that "
        "wasn't you, ignore this email: no results are shown without this code.\n\n"
        f"TraceFind by {brand_line()}\n"
    )
    msg.add_alternative(f"""\
<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;max-width:480px;margin:auto;color:#111827">
  <div style="background:linear-gradient(135deg,#4c1d95,#7c3aed);color:#fff;padding:18px 22px;border-radius:12px 12px 0 0">
    <div style="font-size:11px;letter-spacing:.12em;text-transform:uppercase;opacity:.85">{brand_name()}</div>
    <div style="font-size:20px;font-weight:700">TraceFind verification</div>
  </div>
  <div style="border:1px solid #e5e7eb;border-top:0;padding:22px;border-radius:0 0 12px 12px">
    <p>Your verification code is:</p>
    <p style="font-size:32px;font-weight:800;letter-spacing:.3em;margin:8px 0 16px">{code}</p>
    <p style="color:#6b7280">It expires in {ttl} minutes.</p>
    <p style="color:#6b7280;font-size:13px">Someone asked to check this email address for data-breach
    exposure. If that wasn't you, ignore this email: no results are shown without this code.</p>
  </div>
</div>""", subtype="html")
    return msg


class SmtpMailer:
    def __init__(self, cfg: VerifyConfig):
        self.cfg = cfg

    def send_code(self, to: str, code: str, ttl_minutes: int) -> None:
        c = self.cfg
        msg = _message(c, to, code, ttl_minutes)
        ctx = ssl.create_default_context()
        if c.smtp_ssl:
            with smtplib.SMTP_SSL(c.smtp_host, c.smtp_port, context=ctx, timeout=15) as s:
                if c.smtp_user:
                    s.login(c.smtp_user, c.smtp_password or "")
                s.send_message(msg)
        else:
            with smtplib.SMTP(c.smtp_host, c.smtp_port, timeout=15) as s:
                s.starttls(context=ctx)
                if c.smtp_user:
                    s.login(c.smtp_user, c.smtp_password or "")
                s.send_message(msg)


class ConsoleMailer:
    """Dev mode: logs the code instead of emailing it."""
    def __init__(self):
        self.sent: list[tuple[str, str]] = []

    def send_code(self, to: str, code: str, ttl_minutes: int) -> None:
        self.sent.append((to, code))
        log.warning("[DEV] TraceFind code for %s: %s (SMTP not configured)", to, code)
        print(f"[DEV] TraceFind verification code for {to}: {code}")


def default_mailer(cfg: VerifyConfig) -> Mailer:
    return SmtpMailer(cfg) if cfg.smtp_host else ConsoleMailer()
