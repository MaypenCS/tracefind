"""FastAPI routes for the Exposure Report.

Mount in your app:
    from tracefind.report.router import router as report_router
    app.include_router(report_router)

Endpoints
  POST /api/report/findings   ScanResult JSON -> ExposureReport JSON (for the React panel)
  POST /api/report/html       ScanResult JSON -> downloadable HTML report
  POST /api/report/pdf        ScanResult JSON -> downloadable PDF report
  GET  /api/report/demo       ?format=json|html|pdf — fictional demo report
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

from .demo import demo_previous, demo_scan
from .models import ExposureReport, ScanResult
from .render import PdfUnavailable, filename, render_html, render_pdf
from .scoring import build_report

router = APIRouter(prefix="/api/report", tags=["report"])


def _html(r: ExposureReport, download: bool = True) -> HTMLResponse:
    headers = {"Content-Disposition": f'attachment; filename="{filename(r, "html")}"'} if download else {}
    return HTMLResponse(render_html(r), headers=headers)


def _pdf(r: ExposureReport) -> Response:
    try:
        data = render_pdf(r)
    except PdfUnavailable as e:
        raise HTTPException(status_code=501, detail=str(e))
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename(r, "pdf")}"'})


@router.post("/findings", response_model=ExposureReport)
def findings(scan: ScanResult) -> ExposureReport:
    return build_report(scan)


@router.post("/html")
def html(scan: ScanResult):
    return _html(build_report(scan))


@router.post("/pdf")
def pdf(scan: ScanResult):
    return _pdf(build_report(scan))


@router.get("/demo")
def demo(format: Literal["json", "html", "pdf"] = "json"):
    r = build_report(demo_scan(), previous=demo_previous())
    if format == "html":
        return _html(r, download=False)
    if format == "pdf":
        return _pdf(r)
    return r
