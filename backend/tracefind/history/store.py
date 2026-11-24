"""Local scan history (SQLite).

TraceFind runs as a local app, so history lives on the machine running it. Each saved
scan keeps the normalized ScanResult (breach data *categories* only, never leaked values).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Optional

from tracefind.report.models import ScanResult
from tracefind.report.scoring import build_report

MAX_SCANS_PER_TARGET = 50


def _iso(dt: datetime) -> str:
    """UTC ISO string so text ordering in SQLite matches time ordering."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def normalize_target(target: str) -> str:
    return (target or "").strip().lower()


@dataclass
class ScanSummary:
    id: int
    target: str
    target_type: str
    scanned_at: str
    overall: str
    counts: dict
    username_hits: int
    breaches: int
    breach_checks: bool

    def as_dict(self):
        return self.__dict__.copy()


class HistoryStore:
    def __init__(self, db_path: str | None = None, max_per_target: int = MAX_SCANS_PER_TARGET,
                 max_age_days: int | None = None):
        self.db_path = db_path or os.getenv("TRACEFIND_HISTORY_DB", "tracefind_history.db")
        self.max_per_target = max_per_target
        # Retention: TRACEFIND_HISTORY_DAYS=90 deletes scans older than 90 days (recommended for public sites).
        env_days = os.getenv("TRACEFIND_HISTORY_DAYS", "").strip()
        self.max_age_days = max_age_days if max_age_days is not None else (int(env_days) if env_days.isdigit() else None)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                target        TEXT NOT NULL,
                target_type   TEXT NOT NULL,
                scanned_at    TEXT NOT NULL,
                overall       TEXT NOT NULL,
                counts        TEXT NOT NULL,
                username_hits INTEGER NOT NULL,
                breaches      INTEGER NOT NULL,
                breach_checks INTEGER NOT NULL,
                data          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_scans_target ON scans(target_type, target, scanned_at);
        """)
        self._db.commit()

    def _row(self, r) -> ScanSummary:
        return ScanSummary(id=r[0], target=r[1], target_type=r[2], scanned_at=r[3], overall=r[4],
                           counts=json.loads(r[5]), username_hits=r[6], breaches=r[7],
                           breach_checks=bool(r[8]))

    _COLS = "id, target, target_type, scanned_at, overall, counts, username_hits, breaches, breach_checks"

    def save(self, scan: ScanResult) -> int:
        if scan.is_demo:
            raise ValueError("Demo scans are not saved to history.")
        target = normalize_target(scan.target)
        rep = build_report(scan)
        checks = bool(scan.breaches or scan.pastes or any(
            s.name.lower() in {"haveibeenpwned", "dehashed", "intelx"} and s.status == "ok"
            for s in scan.sources))
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO scans(target, target_type, scanned_at, overall, counts, username_hits, "
                "breaches, breach_checks, data) VALUES(?,?,?,?,?,?,?,?,?)",
                (target, scan.target_type, _iso(scan.scanned_at), rep.overall.value,
                 json.dumps(rep.counts), len(scan.username_hits), len(scan.breaches), int(checks),
                 scan.model_dump_json()))
            new_id = cur.lastrowid
            if self.max_age_days:
                cutoff = _iso(datetime.now(timezone.utc) - timedelta(days=self.max_age_days))
                self._db.execute("DELETE FROM scans WHERE scanned_at < ?", (cutoff,))
            # Retention: keep only the newest N scans per target.
            self._db.execute(
                "DELETE FROM scans WHERE target_type=? AND target=? AND id NOT IN ("
                " SELECT id FROM scans WHERE target_type=? AND target=? ORDER BY scanned_at DESC, id DESC LIMIT ?)",
                (scan.target_type, target, scan.target_type, target, self.max_per_target))
            self._db.commit()
        return new_id

    def get(self, scan_id: int) -> Optional[tuple[ScanSummary, ScanResult]]:
        r = self._db.execute(f"SELECT {self._COLS}, data FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not r:
            return None
        return self._row(r[:9]), ScanResult.model_validate_json(r[9])

    def list_scans(self, target: str, target_type: str) -> list[ScanSummary]:
        rows = self._db.execute(
            f"SELECT {self._COLS} FROM scans WHERE target_type=? AND target=? ORDER BY scanned_at DESC, id DESC",
            (target_type, normalize_target(target))).fetchall()
        return [self._row(r) for r in rows]

    def list_targets(self) -> list[dict]:
        rows = self._db.execute("""
            SELECT s.target, s.target_type, COUNT(*), MAX(s.scanned_at),
                   (SELECT overall FROM scans x WHERE x.target=s.target AND x.target_type=s.target_type
                    ORDER BY x.scanned_at DESC, x.id DESC LIMIT 1)
            FROM scans s GROUP BY s.target, s.target_type ORDER BY MAX(s.scanned_at) DESC""").fetchall()
        return [{"target": r[0], "target_type": r[1], "scans": r[2], "last_scanned_at": r[3],
                 "latest_overall": r[4]} for r in rows]

    def previous(self, scan: ScanResult, before_id: int | None = None) -> Optional[tuple[int, ScanResult]]:
        """Most recent saved scan of the same target that is older than `scan`."""
        q = (f"SELECT id, data FROM scans WHERE target_type=? AND target=? AND scanned_at < ? "
             + ("AND id <> ? " if before_id else "")
             + "ORDER BY scanned_at DESC, id DESC LIMIT 1")
        args = [scan.target_type, normalize_target(scan.target), _iso(scan.scanned_at)]
        if before_id:
            args.append(before_id)
        r = self._db.execute(q, args).fetchone()
        return (r[0], ScanResult.model_validate_json(r[1])) if r else None

    def delete(self, scan_id: int) -> bool:
        with self._lock:
            n = self._db.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount
            self._db.commit()
        return n > 0

    def delete_target(self, target: str, target_type: str) -> int:
        with self._lock:
            n = self._db.execute("DELETE FROM scans WHERE target_type=? AND target=?",
                                 (target_type, normalize_target(target))).rowcount
            self._db.commit()
        return n


@lru_cache
def get_history_store() -> HistoryStore:
    return HistoryStore()
