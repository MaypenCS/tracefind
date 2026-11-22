"""Site definitions for username probing.

The bundled data/sites.json is a snapshot of the Sherlock Project's site list
(MIT License, https://github.com/sherlock-project/sherlock). `update_sites()` pulls the
latest version so detection rules stay current as sites change.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

DATA_DIR = Path(__file__).resolve().parent / "data"
BUNDLED = DATA_DIR / "sites.json"
UPDATED = DATA_DIR / "sites.latest.json"
SOURCE_URL = ("https://raw.githubusercontent.com/sherlock-project/sherlock/master/"
              "sherlock_project/resources/data.json")


@dataclass
class Site:
    name: str
    url: str                      # profile URL template, "{}" = username
    url_main: str
    error_type: str               # status_code | message | response_url
    probe_url: str | None = None  # URL actually requested, if different from url
    error_msgs: list[str] = field(default_factory=list)
    error_codes: list[int] = field(default_factory=list)
    error_url: str | None = None
    regex_check: str | None = None
    method: str | None = None
    payload: dict | None = None
    headers: dict = field(default_factory=dict)
    nsfw: bool = False

    def valid_for(self, username: str) -> bool:
        return not self.regex_check or re.search(self.regex_check, username) is not None


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def parse(raw: dict) -> list[Site]:
    sites = []
    for name, s in raw.items():
        if name.startswith("$") or not isinstance(s, dict) or "url" not in s:
            continue
        etype = s.get("errorType")
        if isinstance(etype, list):  # a few entries combine checks; status_code is the safe common one
            etype = "message" if "message" in etype else etype[0]
        if etype not in ("status_code", "message", "response_url"):
            continue
        sites.append(Site(
            name=name, url=s["url"], url_main=s.get("urlMain", ""), error_type=etype,
            probe_url=s.get("urlProbe"), error_msgs=[str(m) for m in _as_list(s.get("errorMsg"))],
            error_codes=[int(c) for c in _as_list(s.get("errorCode"))], error_url=s.get("errorUrl"),
            regex_check=s.get("regexCheck"), method=s.get("request_method"),
            payload=s.get("request_payload"), headers=s.get("headers") or {}, nsfw=bool(s.get("isNSFW")),
        ))
    return sorted(sites, key=lambda x: x.name.lower())


def load_sites(include_nsfw: bool = False) -> list[Site]:
    path = UPDATED if UPDATED.exists() else BUNDLED
    sites = parse(json.loads(path.read_text(encoding="utf-8")))
    return sites if include_nsfw else [s for s in sites if not s.nsfw]


def update_sites() -> int:
    """Download the latest Sherlock site list. Returns the number of usable sites."""
    r = httpx.get(SOURCE_URL, timeout=30, follow_redirects=True)
    r.raise_for_status()
    raw = r.json()
    n = len(parse(raw))
    if n < 100:
        raise RuntimeError(f"Downloaded site list looks wrong ({n} sites); keeping the current one.")
    UPDATED.write_text(json.dumps(raw, indent=1), encoding="utf-8")
    return n
