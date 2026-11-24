"""FastAPI routes and the scan gate for email verification.

Mount:
    from tracefind.verify.router import router as verify_router
    app.include_router(verify_router)

Routes:
  POST /api/verify/request  {"email": "..."}                 -> {"sent": true}
  POST /api/verify/confirm  {"email": "...", "code": "123456"} -> {"token": "...", "expires_at": 1700000000}
  POST /api/verify/status   {"email": "..."} + X-TraceFind-Verify header -> {"verified": bool}

Gate your scan with:
    from tracefind.verify.router import get_verification_service, VERIFY_HEADER
    verified = svc.is_verified(email, request.headers.get(VERIFY_HEADER))
    scan = gate_scan(scan, verified)
"""
from __future__ import annotations

from functools import lru_cache

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from .service import VerificationService, VerifyError

VERIFY_HEADER = "X-TraceFind-Verify"
router = APIRouter(prefix="/api/verify", tags=["verify"])


@lru_cache
def get_verification_service() -> VerificationService:
    return VerificationService()


class EmailIn(BaseModel):
    email: str


class ConfirmIn(BaseModel):
    email: str
    code: str


def _client_ip(request: Request) -> str:
    # Behind Cloudflare Tunnel, TRACEFIND_TRUST_CLOUDFLARE=1 makes this the real visitor IP.
    from tracefind.public import client_ip
    return client_ip(request)


def _raise(e: VerifyError):
    headers = {"Retry-After": str(e.retry_after)} if e.retry_after else None
    raise HTTPException(status_code=e.status, detail=str(e), headers=headers)


@router.post("/request")
def request_code(body: EmailIn, request: Request,
                 svc: VerificationService = Depends(get_verification_service)):
    try:
        svc.request_code(body.email, _client_ip(request))
    except VerifyError as e:
        _raise(e)
    return {"sent": True}


@router.post("/confirm")
def confirm_code(body: ConfirmIn, svc: VerificationService = Depends(get_verification_service)):
    try:
        t = svc.confirm_code(body.email, body.code)
    except VerifyError as e:
        _raise(e)
    return {"token": t.token, "expires_at": t.expires_at}


@router.post("/status")
def status(body: EmailIn, x_tracefind_verify: str | None = Header(default=None),
           svc: VerificationService = Depends(get_verification_service)):
    return {"verified": svc.is_verified(body.email, x_tracefind_verify)}


def gate_scan(scan, verified: bool):
    """Strip breach and paste results from an unverified email scan.

    Username sweeps stay visible. Breach details (and even whether the address appears
    in a breach) are only shown to someone who proved they own the inbox.
    Works on a report.models.ScanResult.
    """
    if verified or scan.target_type != "email":
        return scan
    from tracefind.report.models import SourceStatus  # local import keeps modules decoupled

    gated = scan.model_copy(deep=True)
    gated.breaches, gated.pastes = [], []
    gated.sources = [s for s in gated.sources
                     if s.name not in {"HaveIBeenPwned", "Dehashed", "IntelX"}]
    gated.sources.append(SourceStatus(
        name="Breach and leak checks", status="skipped",
        detail="verify you own this email address to see breach results"))
    return gated
