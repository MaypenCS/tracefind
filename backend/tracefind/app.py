"""tracefind web API + UI server."""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, breach
from .domain.router import router as domain_router
from .history.router import router as history_router
from .history.router import save_and_report
from .integration import scan_from_breach_results, scan_from_username_results
from .probe import search, valid_username
from .public import public_middleware, public_mode
from .report.router import router as report_router
from .report.scoring import build_report
from .sites import load_sites
from .verify.router import get_verification_service
from .verify.router import router as verify_router

UI_DIR = Path(__file__).resolve().parent / "ui"

app = FastAPI(title="tracefind", version=__version__)
for _r in (report_router, verify_router, history_router, domain_router):
    app.include_router(_r)
app.middleware("http")(public_middleware)  # no-op unless TRACEFIND_PUBLIC=1


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}


@app.get("/api/config")
def config():
    return {"version": __version__, "sites": len(load_sites()), "sites_nsfw": len(load_sites(True)),
            "providers": breach.configured(), "public": public_mode()}


@app.get("/api/search/stream")
async def search_stream(username: str = Query(..., max_length=64), nsfw: bool = False):
    """Server-sent events: one `result` event per site, then a `done` event."""
    if not valid_username(username):
        raise HTTPException(400, "Usernames may contain letters, numbers, dot, underscore and dash.")
    sites = load_sites(include_nsfw=nsfw)

    async def events():
        yield f"event: start\ndata: {json.dumps({'total': len(sites)})}\n\n"
        found = 0
        async for r in search(username, sites):
            found += r.status == "found"
            yield f"event: result\ndata: {json.dumps(r.to_dict())}\n\n"
        yield f"event: done\ndata: {json.dumps({'found': found})}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


PWNED_PASSWORDS = "https://api.pwnedpasswords.com/range/"


@app.get("/api/password/range/{prefix}", response_class=PlainTextResponse)
async def password_range(prefix: str):
    """k-anonymity proxy for HIBP Pwned Passwords (free, no key).
    The browser hashes the password with SHA-1 and sends only the first 5 hex characters.
    The password and its full hash never reach this server or HIBP."""
    if not re.fullmatch(r"[0-9A-Fa-f]{5}", prefix):
        raise HTTPException(400, "Send the first 5 hex characters of the SHA-1 hash.")
    async with httpx.AsyncClient(timeout=15) as c:
        try:
            r = await c.get(PWNED_PASSWORDS + prefix.upper(),
                            headers={"Add-Padding": "true", "User-Agent": "tracefind/1.1 (Maypen Cybersecurity)"})
            r.raise_for_status()
        except httpx.HTTPError:
            raise HTTPException(502, "Couldn't reach Pwned Passwords. Try again shortly.")
    return PlainTextResponse(r.text, headers={"Cache-Control": "no-store"})


class FoundHit(BaseModel):
    site: str
    url: str = ""


class UsernameReportIn(BaseModel):
    username: str
    checked: int = 0
    found: list[FoundHit] = []


@app.post("/api/search/report")
def username_report(body: UsernameReportIn):
    """Called by the UI when a username sweep finishes: saves it to history and returns the
    Exposure Report, including "Changes since last scan" when there's an earlier one."""
    if not valid_username(body.username):
        raise HTTPException(400, "Invalid username.")
    scan = scan_from_username_results(body.username, [h.model_dump() for h in body.found], body.checked)
    out = save_and_report(scan)
    return {"scan_id": out["scan_id"], "report": out["report"].model_dump(mode="json")}


class BreachQuery(BaseModel):
    term: str
    providers: list[str] | None = None


@app.post("/api/breach")
async def breach_lookup(q: BreachQuery, x_tracefind_verify: str | None = Header(default=None)):
    term = q.term.strip()
    if not term or len(term) > 254:
        raise HTTPException(400, "Enter an email address or username.")
    if not any(breach.configured().values()):
        raise HTTPException(400, "No breach providers configured. Add API keys to .env (see .env.example).")
    is_email = bool(breach.EMAIL_RE.match(term))
    # Email breach results only go to someone who proved they own the inbox.
    if is_email and not get_verification_service().is_verified(term, x_tracefind_verify):
        raise HTTPException(403, detail={"message": "Verify you own this email address to see its breach results.",
                                         "verify_required": True})
    results = await breach.lookup(term, q.providers)
    scan = scan_from_breach_results(term, results)
    if is_email:  # email breach checks are saved to history; username breach checks are one-off
        out = save_and_report(scan)
        scan_id, report = out["scan_id"], out["report"]
    else:
        scan_id, report = None, build_report(scan)
    return {"term": term, "results": results, "scan_id": scan_id, "report": report.model_dump(mode="json")}


if UI_DIR.exists():
    app.mount("/assets", StaticFiles(directory=UI_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def ui(path: str):
        f = UI_DIR / path
        return FileResponse(f if path and f.is_file() else UI_DIR / "index.html")
