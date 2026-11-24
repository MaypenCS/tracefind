"""Data models for the TraceFind Exposure Report.

The report layer takes a *normalized* ScanResult. Your existing scanners
(Sherlock-style probing, HIBP, Dehashed, IntelX) only need a small adapter
that maps their output into these models — see adapters.py.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


TargetType = Literal["username", "email", "domain"]


class UsernameHit(BaseModel):
    platform: str
    url: str
    # social, professional, developer, gaming, creative, forum, dating,
    # adult, crypto, finance, marketplace, other
    category: str = "other"


class Breach(BaseModel):
    name: str
    source: str = "HaveIBeenPwned"           # HIBP, Dehashed, ...
    breach_date: Optional[date] = None
    # Data *categories* only, e.g. ["Email addresses", "Passwords"].
    # Never put actual leaked values in here.
    data_classes: list[str] = Field(default_factory=list)
    is_verified: bool = True


class PasteHit(BaseModel):
    source: str = "IntelX"
    title: str = "Untitled"
    found_date: Optional[date] = None
    bucket: Optional[str] = None             # e.g. "pastes", "leaks", "darknet"


class SourceStatus(BaseModel):
    name: str
    status: Literal["ok", "error", "rate_limited", "skipped", "no_key"]
    detail: str = ""


class DomainCheck(BaseModel):
    """One domain security check. status="pass" checks are listed but not scored."""
    id: str
    group: Literal["email", "web", "exposure"]
    status: Literal["pass", "fail", "info"]
    severity: Severity = Severity.INFO
    title: str
    why_it_matters: str = ""
    actions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class DomainResult(BaseModel):
    domain: str
    checks: list[DomainCheck] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    ownership_verified: bool = False
    active_checks_ran: bool = False


class ScanResult(BaseModel):
    target: str
    target_type: TargetType
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    username_hits: list[UsernameHit] = Field(default_factory=list)
    breaches: list[Breach] = Field(default_factory=list)
    pastes: list[PasteHit] = Field(default_factory=list)
    sources: list[SourceStatus] = Field(default_factory=list)
    sites_checked: int = 0
    domain: Optional[DomainResult] = None
    is_demo: bool = False


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    why_it_matters: str
    actions: list[str]
    evidence: list[str] = Field(default_factory=list)
    category: Literal["breach", "paste", "username", "footprint", "domain"]


class ExposureReport(BaseModel):
    scan: ScanResult
    overall: Severity
    summary: str
    findings: list[Finding]
    counts: dict[str, int]
    checklist: list[str]
    unverified: list[str]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    report_id: str
    # Filled when a previous scan of the same target exists (see report/diff.py).
    changes: Optional["ScanDiff"] = None
    changes_summary: list[str] = Field(default_factory=list)


from .diff import ScanDiff  # noqa: E402  (avoid circular import)

ExposureReport.model_rebuild()
