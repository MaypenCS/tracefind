"""Active exposure checks: run ONLY after domain ownership is verified.

Each path is requested once with a plain GET, no redirects followed, and only the first few
KB are read. A hit needs a content signature (e.g. '.git/HEAD' must start with 'ref:'),
so 'soft 404' pages that return 200 for everything don't create false alarms.
Response bodies are never stored, only which signature matched.
"""
from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Optional

import httpx

from tracefind.report.models import DomainCheck, Severity

MAX_BYTES = 4096
DELAY_S = 0.3  # be gentle with the owner's server


@dataclass
class Probe:
    path: str
    label: str
    severity: Severity
    signature: Callable[[bytes, dict], bool]
    why: str
    fix: str


def _txt(b: bytes) -> str:
    return b.decode("utf-8", "replace")


ENV_LINE = re.compile(r"^\s*[A-Z][A-Z0-9_]{2,}\s*=", re.M)

PROBES: list[Probe] = [
    Probe("/.env", "Environment file (.env) is public", Severity.HIGH,
          lambda b, h: len(ENV_LINE.findall(_txt(b))) >= 2 and "<html" not in _txt(b).lower(),
          ".env files usually hold database passwords, API keys and secrets.",
          "Block access to dotfiles in the web server, move .env outside the web root, and ROTATE every secret in it."),
    Probe("/.git/HEAD", "Git repository is public (.git)", Severity.HIGH,
          lambda b, h: _txt(b).lstrip().startswith("ref:") or re.fullmatch(r"\s*[0-9a-f]{40}\s*", _txt(b)) is not None,
          "Anyone can download your full source code and history, including any secrets ever committed.",
          "Delete the .git folder from the web root (deploy without it) and block /.git in the server config."),
    Probe("/.git/config", "Git config is public", Severity.HIGH,
          lambda b, h: "[core]" in _txt(b),
          "Confirms the repository is exposed and can reveal remote URLs and credentials.",
          "Remove .git from the web root and block /.git in the server config."),
    Probe("/.svn/entries", "Subversion metadata is public (.svn)", Severity.HIGH,
          lambda b, h: _txt(b).strip()[:2].isdigit() or "svn:" in _txt(b),
          "Lets attackers reconstruct source code.", "Remove .svn folders from the web root."),
    Probe("/.htpasswd", "Password file (.htpasswd) is public", Severity.HIGH,
          lambda b, h: re.search(r"^[^:\s<]+:\$?(apr1|2y|2a|1)?\$?[./A-Za-z0-9]{10,}", _txt(b), re.M) is not None,
          "Contains usernames and password hashes that can be cracked offline.",
          "Move it outside the web root and change those passwords."),
    Probe("/backup.zip", "Backup archive is downloadable", Severity.HIGH,
          lambda b, h: b[:4] == b"PK\x03\x04",
          "Site backups often include the database and config files with passwords.",
          "Delete backups from the web root and store them somewhere private."),
    Probe("/backup.sql", "Database dump is downloadable", Severity.HIGH,
          lambda b, h: re.search(r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", _txt(b), re.I) is not None,
          "A database dump can expose every customer record and password hash.",
          "Delete it immediately, check access logs for downloads, and treat the data as breached."),
    Probe("/db.sql", "Database dump is downloadable", Severity.HIGH,
          lambda b, h: re.search(r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", _txt(b), re.I) is not None,
          "A database dump can expose every customer record and password hash.",
          "Delete it immediately, check access logs for downloads, and treat the data as breached."),
    Probe("/wp-config.php.bak", "WordPress config backup is public", Severity.HIGH,
          lambda b, h: "DB_PASSWORD" in _txt(b),
          "Contains the database password in plain text.",
          "Delete the file and change the database password."),
    Probe("/server-status", "Apache server-status page is public", Severity.MEDIUM,
          lambda b, h: "Apache Server Status" in _txt(b),
          "Shows live visitor IPs, URLs being requested and internal server details.",
          "Restrict /server-status to localhost in the Apache config."),
    Probe("/phpinfo.php", "phpinfo() page is public", Severity.MEDIUM,
          lambda b, h: "phpinfo()" in _txt(b) or "PHP Version" in _txt(b) and "<table" in _txt(b),
          "Reveals server paths, versions and sometimes environment secrets.",
          "Delete phpinfo.php from the server."),
    Probe("/.DS_Store", "macOS .DS_Store file is public", Severity.LOW,
          lambda b, h: b[4:8] == b"Bud1",
          "Lists file and folder names, which can point attackers to hidden files.",
          "Delete .DS_Store files from the server and block dotfiles."),
]

LOGIN_PATHS = ["/admin", "/admin/", "/wp-admin/", "/wp-login.php", "/administrator/", "/phpmyadmin/",
               "/cpanel", "/login", "/user/login"]
LOGIN_SIG = re.compile(r'(type=["\']?password|wp-login|phpMyAdmin|Joomla|log ?in|sign ?in)', re.I)


def _get(client: httpx.Client, url: str) -> tuple[int, bytes, dict]:
    with client.stream("GET", url, follow_redirects=False) as r:
        body = b""
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) >= MAX_BYTES:
                break
        return r.status_code, body[:MAX_BYTES], dict(r.headers)


def run_probes(host: str, client: httpx.Client, sleep: Callable[[float], None] = time.sleep) -> list[DomainCheck]:
    base = f"https://{host}"
    out: list[DomainCheck] = []

    # Baseline: what does a definitely-missing page look like?
    try:
        b_status, b_body, _ = _get(client, f"{base}/tracefind-{secrets.token_hex(6)}.txt")
    except httpx.HTTPError as e:
        return [DomainCheck(id="probes", group="exposure", status="info", severity=Severity.INFO,
                            title="Exposed-file checks couldn't connect", evidence=[str(e.__class__.__name__)])]

    hits = []
    for p in PROBES:
        sleep(DELAY_S)
        try:
            status, body, headers = _get(client, base + p.path)
        except httpx.HTTPError:
            continue
        if status == 200 and body != b_body and p.signature(body, headers):
            hits.append(p)

    for i, p in enumerate(hits):
        out.append(DomainCheck(id=f"exposed-{i}", group="exposure", status="fail", severity=p.severity,
                               title=p.label, why_it_matters=p.why, actions=[p.fix],
                               evidence=[f"{base}{p.path} returned the file (content not stored)"]))

    logins = []
    for path in LOGIN_PATHS:
        sleep(DELAY_S)
        try:
            status, body, _ = _get(client, base + path)
        except httpx.HTTPError:
            continue
        if status == 401 or (status == 200 and body != b_body and LOGIN_SIG.search(_txt(body))):
            logins.append(f"{base}{path} ({status})")
    if logins:
        out.append(DomainCheck(
            id="login-pages", group="exposure", status="fail", severity=Severity.MEDIUM,
            title=f"Public admin or login page{'s' if len(logins) != 1 else ''} found",
            why_it_matters=("Public admin logins get constant password-guessing attacks. One weak or reused "
                            "password is enough to take over the site."),
            actions=["Turn on two-factor authentication for every admin account.",
                     "Limit admin pages by IP address or VPN, or at least add login rate-limiting.",
                     "Remove admin tools you don't use (e.g. phpMyAdmin)."],
            evidence=logins))

    sleep(DELAY_S)
    try:
        status, body, _ = _get(client, f"{base}/.well-known/security.txt")
        has_sec = status == 200 and "contact:" in _txt(body).lower()
    except httpx.HTTPError:
        has_sec = False
    out.append(DomainCheck(id="security-txt", group="web", status="pass" if has_sec else "info",
                           severity=Severity.INFO,
                           title="security.txt published" if has_sec else "No security.txt",
                           why_it_matters="" if has_sec else "security.txt tells researchers how to report a problem to you.",
                           actions=[] if has_sec else ["Publish /.well-known/security.txt with a Contact: line (see securitytxt.org)."]))
    if not hits:
        out.append(DomainCheck(id="exposed-files", group="exposure", status="pass",
                               title=f"No exposed sensitive files ({len(PROBES)} paths checked)"))
    return out
