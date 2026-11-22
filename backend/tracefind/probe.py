"""Concurrent username probing across sites."""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import asdict, dataclass
from typing import AsyncIterator

import httpx

from .sites import Site

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")

FOUND, NOT_FOUND, INVALID, ERROR = "found", "not_found", "invalid", "error"


@dataclass
class Result:
    site: str
    url: str
    status: str
    http_status: int | None = None
    elapsed_ms: int | None = None
    detail: str = ""

    def to_dict(self):
        return asdict(self)


def valid_username(u: str) -> bool:
    return bool(USERNAME_RE.match(u))


def _fill(template, username):
    if isinstance(template, str):
        return template.replace("{}", username)
    if isinstance(template, dict):
        return {k: _fill(v, username) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, username) for v in template]
    return template


def judge(site: Site, resp: httpx.Response) -> str:
    """Decide found / not_found from a response, using the site's detection rule."""
    code = resp.status_code
    if site.error_type == "status_code":
        if site.error_codes and code in site.error_codes:
            return NOT_FOUND
        return FOUND if 200 <= code < 300 else NOT_FOUND
    if site.error_type == "message":
        body = resp.text
        if any(msg in body for msg in site.error_msgs):
            return NOT_FOUND
        return FOUND if 200 <= code < 400 else NOT_FOUND
    if site.error_type == "response_url":
        # requested without following redirects: a redirect (to errorUrl or elsewhere) means no profile
        return FOUND if 200 <= code < 300 else NOT_FOUND
    return NOT_FOUND


async def check_site(client: httpx.AsyncClient, site: Site, username: str) -> Result:
    profile = _fill(site.url, username)
    if not site.valid_for(username):
        return Result(site.name, profile, INVALID, detail="username format not allowed on this site")
    target = _fill(site.probe_url or site.url, username)
    method = (site.method or ("GET" if site.error_type != "status_code" else "HEAD")).upper()
    kwargs = {"headers": {"User-Agent": UA, **site.headers},
              "follow_redirects": site.error_type != "response_url"}
    if site.payload:
        kwargs["json"] = _fill(site.payload, username)
    t0 = time.perf_counter()
    try:
        resp = await client.request(method, target, **kwargs)
        if method == "HEAD" and resp.status_code in (403, 405, 501):  # some sites reject HEAD
            resp = await client.request("GET", target, **kwargs)
        status = judge(site, resp)
        return Result(site.name, profile, status, resp.status_code, int((time.perf_counter() - t0) * 1000))
    except httpx.TimeoutException:
        return Result(site.name, profile, ERROR, detail="timed out")
    except httpx.HTTPError as e:
        return Result(site.name, profile, ERROR, detail=type(e).__name__)


async def search(username: str, sites: list[Site], concurrency: int = 40,
                 timeout: float = 12.0, transport=None) -> AsyncIterator[Result]:
    """Yield a Result for every site as soon as it finishes."""
    if not valid_username(username):
        raise ValueError("Usernames may contain letters, numbers, dot, underscore and dash (max 64).")
    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(timeout=timeout, limits=limits, transport=transport, http2=False) as client:
        async def run(site):
            async with sem:
                return await check_site(client, site, username)
        for fut in asyncio.as_completed([run(s) for s in sites]):
            yield await fut
