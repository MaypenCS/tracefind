"""Public-site mode for tracefind (TRACEFIND_PUBLIC=1).

When tracefind runs as a public website instead of on your own PC:
  * the username sweep is turned off (it would let anyone look up anyone)
  * scan history is only shown to people who prove they own the email or domain
  * every API route is rate-limited per visitor IP
  * security headers are added and the API docs pages are hidden

Behind Cloudflare Tunnel, set TRACEFIND_TRUST_CLOUDFLARE=1 so the visitor's real IP comes from
the CF-Connecting-IP header. Only do that when tracefind listens on 127.0.0.1 behind the tunnel;
otherwise anyone could fake the header.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse

_TRUE = ("1", "true", "yes", "on")


def public_mode() -> bool:
    return os.getenv("TRACEFIND_PUBLIC", "").strip().lower() in _TRUE


def trust_cloudflare() -> bool:
    return os.getenv("TRACEFIND_TRUST_CLOUDFLARE", "").strip().lower() in _TRUE


def client_ip(request: Request) -> str:
    if trust_cloudflare():
        cf = request.headers.get("cf-connecting-ip", "").strip()
        if cf:
            return cf
    return request.client.host if request.client else "unknown"


# (method or "*", path prefix, max requests, window seconds). First match wins.
RULES: list[tuple[str, str, int, int]] = [
    ("POST", "/api/breach", 10, 3600),
    ("POST", "/api/domain/scan", 6, 3600),
    ("POST", "/api/domain/ownership/check", 30, 3600),
    ("GET", "/api/password/range/", 30, 600),
    ("POST", "/api/verify/confirm", 20, 3600),
    ("POST", "/api/verify/request", 10, 3600),
    ("*", "/api/report/", 60, 3600),
    ("*", "/api/history", 120, 3600),
    ("*", "/api/", 600, 3600),
]


class RateLimiter:
    """In-memory sliding window per (IP, rule). Fine for a single-process server."""

    def __init__(self, rules=RULES, clock=time.monotonic):
        self.rules = rules
        self.clock = clock
        self.hits: dict[tuple[str, int], deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def rule_for(self, method: str, path: str):
        for i, (m, prefix, limit, window) in enumerate(self.rules):
            if (m == "*" or m == method) and path.startswith(prefix):
                return i, limit, window
        return None

    def check(self, ip: str, method: str, path: str) -> int | None:
        """Returns None if allowed, else seconds to wait."""
        r = self.rule_for(method, path)
        if r is None:
            return None
        i, limit, window = r
        now = self.clock()
        with self.lock:
            q = self.hits[(ip, i)]
            while q and now - q[0] >= window:
                q.popleft()
            if len(q) >= limit:
                return max(1, int(window - (now - q[0])) + 1)
            q.append(now)
            if len(self.hits) > 50_000:  # keep memory bounded
                for k in [k for k, v in self.hits.items() if not v][:10_000]:
                    del self.hits[k]
        return None


limiter = RateLimiter()

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # Inline styles are needed by React style props and the printable report.
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                                "frame-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
}

USERNAME_PATHS = ("/api/search/",)


async def public_middleware(request: Request, call_next):
    if not public_mode():
        return await call_next(request)
    path = request.url.path
    if path.startswith(USERNAME_PATHS):
        return JSONResponse({"detail": "The username sweep isn't available on the public site."}, status_code=404)
    if path in ("/docs", "/redoc", "/openapi.json"):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    if path.startswith("/api/"):
        wait = limiter.check(client_ip(request), request.method, path)
        if wait is not None:
            return JSONResponse({"detail": f"Too many requests. Try again in {wait // 60 + 1} minute(s)."},
                                status_code=429, headers={"Retry-After": str(wait)})
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if "server" in response.headers:
        del response.headers["server"]
    return response
