"""FastAPI routes for scan history.

Mount:
    from tracefind.history.router import router as history_router
    app.include_router(history_router)

Routes
  GET    /api/history/targets                         all targets with a saved scan
  GET    /api/history?target=&target_type=            scans for one target, newest first
  GET    /api/history/scan/{id}                       one saved ScanResult
  GET    /api/history/compare?from_id=&to_id=         ScanDiff between two scans
  GET    /api/history/scan/{id}/report?format=json|html|pdf
                                                      report for a saved scan, with "Changes since"
  DELETE /api/history/scan/{id}                       delete one scan
  DELETE /api/history?target=&target_type=            delete all scans for a target

Email targets need the verification header (X-TraceFind-Verify), the same as scanning,
because history holds breach results.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from tracefind.report.diff import diff_scans
from tracefind.report.router import _html, _pdf
from tracefind.report.scoring import build_report

from .store import HistoryStore, get_history_store

router = APIRouter(prefix="/api/history", tags=["history"])
TargetType = Literal["username", "email", "domain"]


_owner_cache: dict[str, float] = {}


def _domain_owner_ok(domain: str) -> bool:
    """Public mode: domain history needs the live _tracefind ownership record (cached 10 min)."""
    import time
    now = time.time()
    if _owner_cache.get(domain, 0) > now:
        return True
    from tracefind.domain.email_auth import DnsPythonResolver
    from tracefind.domain.ownership import check_ownership
    from tracefind.domain.router import _secret
    from tracefind.domain.scanner import make_client
    with make_client() as c:
        ok = bool(check_ownership(domain, _secret(), DnsPythonResolver(), c))
    if ok:
        _owner_cache[domain] = now + 600
    return ok


def _verify_ok(target: str, target_type: str, token: str | None) -> bool:
    from tracefind.public import public_mode
    if public_mode():
        if target_type == "username":
            return False
        if target_type == "domain":
            return _domain_owner_ok(target.strip().lower())
    if target_type != "email":
        return True
    try:
        from tracefind.verify.router import get_verification_service
    except ImportError:  # verification module not installed
        return True
    return get_verification_service().is_verified(target, token)


def _require(target: str, target_type: str, token: str | None):
    if not _verify_ok(target, target_type, token):
        msg = {"email": "Verify you own this email address to view its history.",
               "domain": "Add this domain's TraceFind ownership record (see the Domain tab) to view its history.",
               "username": "Username history isn't available on the public site."}[target_type]
        raise HTTPException(403, msg)


@router.get("/targets")
def targets(store: HistoryStore = Depends(get_history_store)):
    # Email targets are listed so the UI can offer them, but their scans stay gated.
    # On the public site nobody gets a list of what other people scanned.
    from tracefind.public import public_mode
    if public_mode():
        return []
    return store.list_targets()


@router.get("")
def list_scans(target: str, target_type: TargetType,
               x_tracefind_verify: str | None = Header(default=None),
               store: HistoryStore = Depends(get_history_store)):
    _require(target, target_type, x_tracefind_verify)
    return [s.as_dict() for s in store.list_scans(target, target_type)]


def _load(store: HistoryStore, scan_id: int, token: str | None):
    got = store.get(scan_id)
    if not got:
        raise HTTPException(404, "Scan not found.")
    summary, scan = got
    _require(scan.target, scan.target_type, token)
    return summary, scan


@router.get("/scan/{scan_id}")
def get_scan(scan_id: int, x_tracefind_verify: str | None = Header(default=None),
             store: HistoryStore = Depends(get_history_store)):
    return _load(store, scan_id, x_tracefind_verify)[1]


@router.get("/compare")
def compare(from_id: int, to_id: int, x_tracefind_verify: str | None = Header(default=None),
            store: HistoryStore = Depends(get_history_store)):
    _, a = _load(store, from_id, x_tracefind_verify)
    _, b = _load(store, to_id, x_tracefind_verify)
    if (a.target.lower(), a.target_type) != (b.target.lower(), b.target_type):
        raise HTTPException(400, "Both scans must be for the same target.")
    if a.scanned_at > b.scanned_at:
        (a, from_id), (b, to_id) = (b, to_id), (a, from_id)
    d = diff_scans(a, b, from_id, to_id)
    return {**d.model_dump(mode="json"), "summary": d.summary(), "has_changes": d.has_changes}


@router.get("/scan/{scan_id}/report")
def scan_report(scan_id: int, format: Literal["json", "html", "pdf"] = "json",
                x_tracefind_verify: str | None = Header(default=None),
                store: HistoryStore = Depends(get_history_store)):
    _, scan = _load(store, scan_id, x_tracefind_verify)
    prev = store.previous(scan, before_id=scan_id)
    r = build_report(scan, previous=prev[1] if prev else None,
                     previous_id=prev[0] if prev else None, current_id=scan_id)
    if format == "html":
        return _html(r)
    if format == "pdf":
        return _pdf(r)
    return r


@router.delete("/scan/{scan_id}")
def delete_scan(scan_id: int, x_tracefind_verify: str | None = Header(default=None),
                store: HistoryStore = Depends(get_history_store)):
    _load(store, scan_id, x_tracefind_verify)
    store.delete(scan_id)
    return {"deleted": 1}


@router.delete("")
def delete_target(target: str, target_type: TargetType,
                  x_tracefind_verify: str | None = Header(default=None),
                  store: HistoryStore = Depends(get_history_store)):
    _require(target, target_type, x_tracefind_verify)
    return {"deleted": store.delete_target(target, target_type)}


def save_and_report(scan, store: HistoryStore | None = None) -> dict:
    """Helper for your scan endpoint: save the scan and return
    {"scan_id": int, "report": ExposureReport} with "Changes since last scan" filled in."""
    store = store or get_history_store()
    prev = store.previous(scan)
    scan_id = store.save(scan)
    rep = build_report(scan, previous=prev[1] if prev else None,
                       previous_id=prev[0] if prev else None, current_id=scan_id)
    return {"scan_id": scan_id, "report": rep}
