"""tracefind web API + UI server."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, breach
from .probe import search, valid_username
from .sites import load_sites

UI_DIR = Path(__file__).resolve().parent / "ui"

app = FastAPI(title="tracefind", version=__version__)


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}


@app.get("/api/config")
def config():
    return {"version": __version__, "sites": len(load_sites()), "sites_nsfw": len(load_sites(True)),
            "providers": breach.configured()}


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


class BreachQuery(BaseModel):
    term: str
    providers: list[str] | None = None


@app.post("/api/breach")
async def breach_lookup(q: BreachQuery):
    term = q.term.strip()
    if not term or len(term) > 254:
        raise HTTPException(400, "Enter an email address or username.")
    if not any(breach.configured().values()):
        raise HTTPException(400, "No breach providers configured. Add API keys to .env (see .env.example).")
    return {"term": term, "results": await breach.lookup(term, q.providers)}


if UI_DIR.exists():
    app.mount("/assets", StaticFiles(directory=UI_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def ui(path: str):
        f = UI_DIR / path
        return FileResponse(f if path and f.is_file() else UI_DIR / "index.html")
