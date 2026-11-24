"""Compare two scans of the same target."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from .models import Breach, PasteHit, ScanResult, UsernameHit


class BreachChange(BaseModel):
    name: str
    new_data_classes: list[str]


class ScanDiff(BaseModel):
    previous_scanned_at: datetime
    current_scanned_at: datetime
    previous_id: Optional[int] = None
    current_id: Optional[int] = None
    new_accounts: list[UsernameHit] = Field(default_factory=list)
    removed_accounts: list[UsernameHit] = Field(default_factory=list)
    new_breaches: list[Breach] = Field(default_factory=list)
    expanded_breaches: list[BreachChange] = Field(default_factory=list)
    new_pastes: list[PasteHit] = Field(default_factory=list)
    # True when the previous scan included breach checks but this one didn't (or vice versa),
    # so breach changes can't be compared fairly.
    breach_coverage_changed: bool = False
    # Domain scans
    new_subdomains: list[str] = Field(default_factory=list)
    new_problems: list[str] = Field(default_factory=list)      # check titles now failing
    fixed_problems: list[str] = Field(default_factory=list)    # check titles no longer failing

    @property
    def has_changes(self) -> bool:
        return bool(self.new_accounts or self.removed_accounts or self.new_breaches
                    or self.expanded_breaches or self.new_pastes or self.new_subdomains
                    or self.new_problems or self.fixed_problems)

    def summary(self) -> list[str]:
        out = []
        n = len(self.new_accounts)
        if n:
            out.append(f"{n} new account{'s' if n != 1 else ''} using this username: "
                       + ", ".join(h.platform for h in self.new_accounts[:8])
                       + ("…" if n > 8 else ""))
        if self.removed_accounts:
            out.append(f"{len(self.removed_accounts)} account{'s' if len(self.removed_accounts) != 1 else ''} "
                       "no longer found (closed, renamed or temporarily unreachable)")
        for b in self.new_breaches:
            out.append(f"New breach: {b.name}")
        for c in self.expanded_breaches:
            out.append(f"{c.name}: newly reported data types ({', '.join(c.new_data_classes)})")
        if self.new_pastes:
            out.append(f"{len(self.new_pastes)} new paste or leak record{'s' if len(self.new_pastes) != 1 else ''}")
        for t in self.fixed_problems:
            out.append(f"Fixed: {t}")
        for t in self.new_problems:
            out.append(f"New problem: {t}")
        if self.new_subdomains:
            n = len(self.new_subdomains)
            out.append(f"{n} new subdomain{'s' if n != 1 else ''} in certificate logs: "
                       + ", ".join(self.new_subdomains[:6]) + ("…" if n > 6 else ""))
        if self.breach_coverage_changed:
            out.append("Breach checks ran in only one of the two scans, so breach changes may be incomplete")
        if not out:
            out.append("No changes since the previous scan")
        return out


def _had_breach_checks(s: ScanResult) -> bool:
    if s.breaches or s.pastes:
        return True
    names = {"haveibeenpwned", "dehashed", "intelx"}
    return any(x.name.lower() in names and x.status == "ok" for x in s.sources)


def diff_scans(previous: ScanResult, current: ScanResult,
               previous_id: int | None = None, current_id: int | None = None) -> ScanDiff:
    prev_hits = {h.platform.strip().lower(): h for h in previous.username_hits}
    cur_hits = {h.platform.strip().lower(): h for h in current.username_hits}

    prev_b = {b.name.strip().lower(): b for b in previous.breaches}
    new_breaches, expanded = [], []
    for key, b in ((b.name.strip().lower(), b) for b in current.breaches):
        if key not in prev_b:
            new_breaches.append(b)
        else:
            added = sorted(set(b.data_classes) - set(prev_b[key].data_classes))
            if added:
                expanded.append(BreachChange(name=b.name, new_data_classes=added))

    prev_p = {(p.source, p.title) for p in previous.pastes}
    new_pastes = [p for p in current.pastes if (p.source, p.title) not in prev_p]

    new_subs, new_probs, fixed = [], [], []
    if previous.domain and current.domain:
        new_subs = sorted(set(current.domain.subdomains) - set(previous.domain.subdomains))
        if not previous.domain.subdomains:  # previous lookup may have failed; don't call everything new
            new_subs = []
        prev_fail = {c.id: c.title for c in previous.domain.checks if c.status == "fail"}
        cur_fail = {c.id: c.title for c in current.domain.checks if c.status == "fail"}
        cur_ids = {c.id for c in current.domain.checks}
        new_probs = [t for i, t in cur_fail.items() if i not in prev_fail]
        # Only "fixed" if the check actually ran again and passed.
        fixed = [t for i, t in prev_fail.items() if i not in cur_fail and i in cur_ids]
        if previous.domain.active_checks_ran != current.domain.active_checks_ran:
            new_probs = [t for i, t in cur_fail.items() if i not in prev_fail and not i.startswith(("exposed-", "login-"))]
            fixed = [t for i, t in prev_fail.items() if i not in cur_fail and i in cur_ids]

    coverage_changed = (previous.target_type != "domain"
                        and _had_breach_checks(previous) != _had_breach_checks(current))
    if coverage_changed and not _had_breach_checks(previous):
        # Previous scan was unverified/username-only: everything would look "new". Don't claim that.
        new_breaches, expanded, new_pastes = [], [], []

    return ScanDiff(
        previous_scanned_at=previous.scanned_at, current_scanned_at=current.scanned_at,
        previous_id=previous_id, current_id=current_id,
        new_accounts=[h for k, h in cur_hits.items() if k not in prev_hits],
        removed_accounts=[h for k, h in prev_hits.items() if k not in cur_hits],
        new_breaches=new_breaches, expanded_breaches=expanded, new_pastes=new_pastes,
        breach_coverage_changed=coverage_changed,
        new_subdomains=new_subs, new_problems=new_probs, fixed_problems=fixed,
    )
