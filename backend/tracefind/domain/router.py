"""FastAPI routes for domain scanning.

Mount:
    from tracefind.domain.router import router as domain_router
    app.include_router(domain_router)

Routes
  POST /api/domain/scan               {"domain": "example.ca", "active": false}
  GET  /api/domain/ownership?domain=  how to prove ownership (DNS TXT record or file)
  POST /api/domain/ownership/check    {"domain": "example.ca"} -> {"verified": bool, "method": "dns"|"file"|null}
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from tracefind.report.scoring import build_report

from .email_auth import DnsPythonResolver
from .ownership import check_ownership, instructions
from .scanner import OwnershipRequired, make_client, scan_domain
from .util import DomainError, normalize_domain

router = APIRouter(prefix="/api/domain", tags=["domain"])


def _secret() -> bytes:
    try:
        from tracefind.verify.config import _secret as s
    except ImportError:
        import os
        return os.getenv("TRACEFIND_SECRET", "change-me").encode()
    return s()


class DomainIn(BaseModel):
    domain: str
    active: bool = False


def _norm(d: str) -> str:
    try:
        return normalize_domain(d)
    except DomainError as e:
        raise HTTPException(400, str(e))


@router.get("/ownership")
def ownership(domain: str):
    return instructions(_norm(domain), _secret())


@router.post("/ownership/check")
async def ownership_check(body: DomainIn):
    d = _norm(body.domain)

    def run():
        with make_client() as c:
            return check_ownership(d, _secret(), DnsPythonResolver(), c)

    method = await run_in_threadpool(run)
    return {"domain": d, "verified": bool(method), "method": method}


@router.post("/scan")
async def scan(body: DomainIn):
    d = _norm(body.domain)
    try:
        result = await run_in_threadpool(scan_domain, d, secret=_secret(), active=body.active)
    except OwnershipRequired:
        raise HTTPException(403, detail={
            "message": "Verify you own this domain before running exposed-file checks.",
            "ownership": instructions(d, _secret())})
    except DomainError as e:
        raise HTTPException(400, str(e))

    try:  # Save to history when that module is installed.
        from tracefind.history import save_and_report
    except ImportError:
        return {"scan_id": None, "scan": result.model_dump(mode="json"),
                "report": build_report(result).model_dump(mode="json")}
    out = save_and_report(result)
    return {"scan_id": out["scan_id"], "scan": result.model_dump(mode="json"),
            "report": out["report"].model_dump(mode="json")}
