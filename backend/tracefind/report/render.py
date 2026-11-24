"""Render an ExposureReport to HTML or PDF."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .brand import brand_line, brand_name
from .models import ExposureReport
from .scoring import CATEGORY_LABELS

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),  # target/URLs are user-controlled — keep escaping on
)


def _grouped_hits(report: ExposureReport):
    groups = defaultdict(list)
    for h in report.scan.username_hits:
        groups[CATEGORY_LABELS.get(h.category, "Other")].append(h)
    return sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))


def render_html(report: ExposureReport) -> str:
    return _env.get_template("exposure_report.html").render(r=report, grouped_hits=_grouped_hits(report),
                                                            brand_line=brand_line(), brand_name=brand_name())


class PdfUnavailable(RuntimeError):
    pass


def render_pdf(report: ExposureReport) -> bytes:
    try:
        from weasyprint import HTML  # optional dependency
    except (ImportError, OSError) as e:  # OSError: GTK/Pango libs missing on Windows
        raise PdfUnavailable(
            "PDF export needs WeasyPrint (pip install weasyprint; on Windows also install the "
            "GTK3 runtime). The HTML report can still be printed to PDF from the browser."
        ) from e
    return HTML(string=render_html(report)).write_pdf()


def filename(report: ExposureReport, ext: str) -> str:
    return f"TraceFind-Exposure-Report-{report.report_id}.{ext}"
