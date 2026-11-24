"""Lifecycle store on stdlib sqlite3."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any

from cspm.contracts import Finding, FindingState, ScanMode, Severity, Source, VerificationStatus, verification_for
from cspm.reports.model import SEVERITY_ORDER, finding_to_dict
from cspm.reports.redact import Redactor

SLA_DAYS: dict[Severity, int | None] = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFO: None,
}

ACTIVE_STATES: frozenset[FindingState] = frozenset(
    {FindingState.NEW, FindingState.OPEN, FindingState.ASSIGNED, FindingState.FIXED_CLAIMED, FindingState.REOPENED}
)
_ASSIGNABLE = frozenset({FindingState.NEW, FindingState.OPEN, FindingState.ASSIGNED, FindingState.REOPENED})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, mode TEXT NOT NULL, started_at TEXT,
    finished_at TEXT NOT NULL, sources TEXT NOT NULL, providers TEXT, active_after INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, source TEXT NOT NULL, rule_id TEXT NOT NULL, resource_id TEXT NOT NULL,
    resource_type TEXT NOT NULL, provider TEXT NOT NULL, band TEXT NOT NULL, score REAL NOT NULL,
    title TEXT NOT NULL, state TEXT NOT NULL, verification_status TEXT NOT NULL, owner TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, due_date TEXT, closed_at TEXT,
    last_scan_id TEXT NOT NULL, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS history (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL, scan_id TEXT, at TEXT NOT NULL,
    from_state TEXT, to_state TEXT NOT NULL, verification_status TEXT NOT NULL, actor TEXT, note TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, band TEXT NOT NULL, score REAL NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);
CREATE INDEX IF NOT EXISTS history_finding ON history (finding_id, seq);
"""


class InvalidTransitionError(ValueError):
    """Raised when a manual lifecycle step is not allowed from the current state."""


def due_date_for(band: Severity, start: datetime) -> datetime | None:
    """SLA due date for a band counted from start; info findings have no SLA."""
    days = SLA_DAYS[band]
    return None if days is None else start + timedelta(days=days)


@dataclass(frozen=True, slots=True)
class ScanMeta:
    """What the store needs to know about one scan.

    `sources` and `providers` set the scope a rescan can close: a Trivy import must
    not close assay findings and an Azure scan must not close AWS findings.
    `providers` of None means every provider.
    """

    scan_id: str
    mode: ScanMode
    finished_at: datetime
    started_at: datetime | None = None
    sources: frozenset[Source] = frozenset({Source.ASSAY})
    providers: frozenset[str] | None = None

    @classmethod
    def from_dict(cls, scan: Mapping[str, Any], sources: Iterable[Source] = (Source.ASSAY,)) -> ScanMeta:
        """Build from the `scan` object of a findings report."""
        providers = scan.get("providers")
        started = scan.get("started_at")
        return cls(
            scan_id=str(scan["scan_id"]),
            mode=ScanMode(scan["mode"]),
            finished_at=datetime.fromisoformat(scan["finished_at"]),
            started_at=datetime.fromisoformat(started) if started else None,
            sources=frozenset(sources),
            providers=frozenset(providers) if providers else None,
        )


@dataclass(frozen=True, slots=True)
class ScanDiff:
    """Lifecycle effect of one recorded scan, as finding ids."""

    scan_id: str
    mode: ScanMode
    new: tuple[str, ...] = ()
    still_open: tuple[str, ...] = ()
    reopened: tuple[str, ...] = ()
    closed: tuple[str, ...] = ()

    @property
    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "still_open": len(self.still_open),
            "reopened": len(self.reopened),
            "closed": len(self.closed),
        }


@dataclass(frozen=True, slots=True)
class FindingDelta:
    """Comparison of what two scans observed; backs `cspm diff`."""

    scan_a: str
    scan_b: str
    added: tuple[str, ...]
    removed: tuple[str, ...]
    persisting: tuple[str, ...]
    band_changed: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class TrendPoint:
    """Per-scan totals; backs `cspm trend`."""

    scan_id: str
    finished_at: datetime
    mode: ScanMode
    observed: int
    by_band: dict[str, int]
    new: int
    reopened: int
    closed: int
    active_after: int


@dataclass(frozen=True, slots=True)
class Transition:
    finding_id: str
    scan_id: str | None
    at: datetime
    from_state: FindingState | None
    to_state: FindingState
    verification_status: VerificationStatus
    actor: str | None
    note: str


@dataclass(frozen=True, slots=True)
class StoredFinding:
    id: str
    source: Source
    rule_id: str
    resource_id: str
    resource_type: str
    provider: str
    band: Severity
    score: float
    title: str
    state: FindingState
    verification_status: VerificationStatus
    owner: str | None
    first_seen: datetime
    last_seen: datetime
    due_date: datetime | None
    closed_at: datetime | None
    last_scan_id: str
    data: dict[str, Any] = field(default_factory=dict)


def _ts(value: datetime) -> str:
    return value.isoformat()


def _opt_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class Store:
    """SQLite-backed finding lifecycle. Evidence and identifiers are redacted before they are written."""

    def __init__(self, path: Path | str, *, salt: str = "") -> None:
        self._db = sqlite3.connect(str(path))
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._redactor = Redactor(salt)

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._db:
            yield self._db

    def record_scan(self, scan_meta: ScanMeta | Mapping[str, Any], findings: Iterable[Finding]) -> ScanDiff:
        """Apply one scan: open what is seen, close what is in scope and no longer seen."""
        meta = scan_meta if isinstance(scan_meta, ScanMeta) else ScanMeta.from_dict(scan_meta)
        at = meta.finished_at
        seen: dict[str, Finding] = {}
        for f in findings:
            prior = seen.get(f.id)
            if prior is None or f.score > prior.score:
                seen[f.id] = f
        new: list[str] = []
        still: list[str] = []
        reopened: list[str] = []
        closed: list[str] = []
        with self._tx() as db:
            if db.execute("SELECT 1 FROM scans WHERE scan_id = ?", (meta.scan_id,)).fetchone():
                raise ValueError(f"scan {meta.scan_id} already recorded")
            seq = db.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM scans").fetchone()[0]
            for fid, f in seen.items():
                row = db.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
                bucket = self._observe(db, meta, f, row)
                {"new": new, "still": still, "reopened": reopened}[bucket].append(fid)
                db.execute(
                    "INSERT INTO observations (scan_id, finding_id, band, score) VALUES (?, ?, ?, ?)",
                    (meta.scan_id, fid, f.band.value, f.score),
                )
            for row in db.execute("SELECT * FROM findings").fetchall():
                if row["id"] in seen or FindingState(row["state"]) not in ACTIVE_STATES:
                    continue
                if not self._in_scope(meta, row):
                    continue
                self._close(db, meta, row)
                closed.append(row["id"])
            active = sum(
                1 for r in db.execute("SELECT state FROM findings") if FindingState(r["state"]) in ACTIVE_STATES
            )
            db.execute(
                "INSERT INTO scans (scan_id, seq, mode, started_at, finished_at, sources, providers, active_after)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    meta.scan_id,
                    seq,
                    meta.mode.value,
                    _ts(meta.started_at) if meta.started_at else None,
                    _ts(at),
                    json.dumps(sorted(s.value for s in meta.sources)),
                    json.dumps(sorted(meta.providers)) if meta.providers is not None else None,
                    active,
                ),
            )
        return ScanDiff(meta.scan_id, meta.mode, tuple(new), tuple(still), tuple(reopened), tuple(closed))

    @staticmethod
    def _in_scope(meta: ScanMeta, row: sqlite3.Row) -> bool:
        if Source(row["source"]) not in meta.sources:
            return False
        return meta.providers is None or row["provider"] in meta.providers

    def _observe(self, db: sqlite3.Connection, meta: ScanMeta, f: Finding, row: sqlite3.Row | None) -> str:
        at = meta.finished_at
        data: dict[str, Any] = self._redactor.value(finding_to_dict(f))
        data["id"] = f.id
        fields = {
            "band": f.band.value,
            "score": f.score,
            "title": data["title"],
            "resource_id": data["resource_id"],
            "last_seen": _ts(at),
            "last_scan_id": meta.scan_id,
            "data": json.dumps(data, sort_keys=True),
        }
        if row is None:
            due = due_date_for(f.band, at)
            db.execute(
                "INSERT INTO findings (id, source, rule_id, resource_id, resource_type, provider, band, score, title,"
                " state, verification_status, owner, first_seen, last_seen, due_date, closed_at, last_scan_id, data)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, ?, ?)",
                (
                    f.id,
                    f.source.value,
                    f.rule_id,
                    fields["resource_id"],
                    f.resource_type,
                    f.provider,
                    fields["band"],
                    f.score,
                    fields["title"],
                    FindingState.NEW.value,
                    VerificationStatus.NOT_VERIFIED.value,
                    _ts(at),
                    _ts(at),
                    _ts(due) if due else None,
                    meta.scan_id,
                    fields["data"],
                ),
            )
            self._log(
                db,
                f.id,
                meta.scan_id,
                at,
                src=None,
                dst=FindingState.NEW,
                status=VerificationStatus.NOT_VERIFIED,
                note="first seen",
            )
            return "new"
        state = FindingState(row["state"])
        target = state
        note = ""
        bucket = "still"
        if state is FindingState.NEW:
            target, note = FindingState.OPEN, "seen again"
        elif state is FindingState.FIXED_CLAIMED:
            target, note, bucket = FindingState.REOPENED, "rescan still fails after fix claim", "reopened"
        elif state is FindingState.VERIFIED_CLOSED:
            target, note, bucket = FindingState.REOPENED, "issue returned after closure", "reopened"
            due = due_date_for(f.band, at)
            fields["due_date"] = _ts(due) if due else None
            fields["closed_at"] = None
        if target is not state:
            fields["state"] = target.value
            fields["verification_status"] = VerificationStatus.NOT_VERIFIED.value
            self._log(
                db, f.id, meta.scan_id, at, src=state, dst=target, status=VerificationStatus.NOT_VERIFIED, note=note
            )
        assignments = ", ".join(f"{k} = ?" for k in fields)
        db.execute(f"UPDATE findings SET {assignments} WHERE id = ?", (*fields.values(), f.id))  # noqa: S608
        return bucket

    def _close(self, db: sqlite3.Connection, meta: ScanMeta, row: sqlite3.Row) -> None:
        state = FindingState(row["state"])
        status = verification_for(meta.mode)
        note = "absent on rescan" + (" after fix claim" if state is FindingState.FIXED_CLAIMED else "")
        db.execute(
            "UPDATE findings SET state = ?, verification_status = ?, closed_at = ? WHERE id = ?",
            (FindingState.VERIFIED_CLOSED.value, status.value, _ts(meta.finished_at), row["id"]),
        )
        self._log(
            db,
            row["id"],
            meta.scan_id,
            meta.finished_at,
            src=state,
            dst=FindingState.VERIFIED_CLOSED,
            status=status,
            note=note,
        )

    @staticmethod
    def _log(
        db: sqlite3.Connection,
        finding_id: str,
        scan_id: str | None,
        at: datetime,
        *,
        src: FindingState | None,
        dst: FindingState,
        status: VerificationStatus,
        note: str,
        actor: str | None = None,
    ) -> None:
        db.execute(
            "INSERT INTO history (finding_id, scan_id, at, from_state, to_state, verification_status, actor, note)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding_id,
                scan_id,
                _ts(at),
                src.value if src else None,
                dst.value,
                status.value,
                actor,
                note,
            ),
        )

    def _manual(
        self,
        finding_id: str,
        allowed: frozenset[FindingState],
        target: FindingState,
        *,
        note: str,
        at: datetime | None,
        actor: str | None,
        owner: str | None = None,
    ) -> StoredFinding:
        when = at or datetime.now(UTC)
        with self._tx() as db:
            row = db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if row is None:
                raise KeyError(finding_id)
            state = FindingState(row["state"])
            if state not in allowed:
                raise InvalidTransitionError(f"{finding_id}: cannot go from {state.value} to {target.value}")
            new_owner = owner if owner is not None else row["owner"]
            db.execute("UPDATE findings SET state = ?, owner = ? WHERE id = ?", (target.value, new_owner, finding_id))
            status = VerificationStatus(row["verification_status"])
            self._log(db, finding_id, None, when, src=state, dst=target, status=status, note=note, actor=actor)
            return self._stored(db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone())

    def assign(
        self, finding_id: str, owner: str, *, at: datetime | None = None, actor: str | None = None
    ) -> StoredFinding:
        """Give an active finding an owner."""
        if not owner.strip():
            raise ValueError("owner must not be empty")
        return self._manual(
            finding_id, _ASSIGNABLE, FindingState.ASSIGNED, note=f"assigned to {owner}", at=at, actor=actor, owner=owner
        )

    def claim_fixed(
        self, finding_id: str, *, at: datetime | None = None, actor: str | None = None, note: str = ""
    ) -> StoredFinding:
        """Mark a fix as claimed; only a later rescan can close or reopen it."""
        text = f"fix claimed: {note}" if note else "fix claimed"
        return self._manual(finding_id, _ASSIGNABLE, FindingState.FIXED_CLAIMED, note=text, at=at, actor=actor)

    def get(self, finding_id: str) -> StoredFinding | None:
        row = self._db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._stored(row) if row else None

    def findings(self, states: Iterable[FindingState] | None = None) -> list[StoredFinding]:
        """Stored findings, optionally filtered by state, ordered by band then id."""
        wanted = set(states) if states is not None else None
        rows = [self._stored(r) for r in self._db.execute("SELECT * FROM findings")]
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return sorted(
            (r for r in rows if wanted is None or r.state in wanted), key=lambda r: (rank[r.band.value], r.id)
        )

    def overdue(self, now: datetime) -> list[StoredFinding]:
        """Active findings past their SLA due date."""
        return [f for f in self.findings(ACTIVE_STATES) if f.due_date is not None and f.due_date < now]

    def history(self, finding_id: str | None = None) -> list[Transition]:
        """Transitions in the order they happened."""
        if finding_id is None:
            rows = self._db.execute("SELECT * FROM history ORDER BY seq").fetchall()
        else:
            rows = self._db.execute("SELECT * FROM history WHERE finding_id = ? ORDER BY seq", (finding_id,)).fetchall()
        return [
            Transition(
                finding_id=r["finding_id"],
                scan_id=r["scan_id"],
                at=datetime.fromisoformat(r["at"]),
                from_state=FindingState(r["from_state"]) if r["from_state"] else None,
                to_state=FindingState(r["to_state"]),
                verification_status=VerificationStatus(r["verification_status"]),
                actor=r["actor"],
                note=r["note"],
            )
            for r in rows
        ]

    def scan_ids(self) -> list[str]:
        return [r[0] for r in self._db.execute("SELECT scan_id FROM scans ORDER BY seq")]

    def _observed(self, scan_id: str) -> dict[str, str]:
        if not self._db.execute("SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)).fetchone():
            raise KeyError(scan_id)
        rows = self._db.execute("SELECT finding_id, band FROM observations WHERE scan_id = ?", (scan_id,))
        return {r["finding_id"]: r["band"] for r in rows}

    def diff(self, scan_a: str, scan_b: str) -> FindingDelta:
        """What scan_b saw that scan_a did not, and the reverse."""
        a = self._observed(scan_a)
        b = self._observed(scan_b)
        both = sorted(a.keys() & b.keys())
        return FindingDelta(
            scan_a=scan_a,
            scan_b=scan_b,
            added=tuple(sorted(b.keys() - a.keys())),
            removed=tuple(sorted(a.keys() - b.keys())),
            persisting=tuple(both),
            band_changed=tuple((fid, a[fid], b[fid]) for fid in both if a[fid] != b[fid]),
        )

    def trend(self) -> list[TrendPoint]:
        """One point per recorded scan in recording order."""
        points: list[TrendPoint] = []
        for scan in self._db.execute("SELECT * FROM scans ORDER BY seq").fetchall():
            observed = self._observed(scan["scan_id"])
            by_band = dict.fromkeys(SEVERITY_ORDER, 0)
            for band in observed.values():
                by_band[band] += 1
            moves = self._db.execute(
                "SELECT from_state, to_state FROM history WHERE scan_id = ?", (scan["scan_id"],)
            ).fetchall()
            points.append(
                TrendPoint(
                    scan_id=scan["scan_id"],
                    finished_at=datetime.fromisoformat(scan["finished_at"]),
                    mode=ScanMode(scan["mode"]),
                    observed=len(observed),
                    by_band=by_band,
                    new=sum(1 for m in moves if m["from_state"] is None),
                    reopened=sum(1 for m in moves if m["to_state"] == FindingState.REOPENED.value),
                    closed=sum(1 for m in moves if m["to_state"] == FindingState.VERIFIED_CLOSED.value),
                    active_after=scan["active_after"],
                )
            )
        return points

    @staticmethod
    def _stored(row: sqlite3.Row) -> StoredFinding:
        return StoredFinding(
            id=row["id"],
            source=Source(row["source"]),
            rule_id=row["rule_id"],
            resource_id=row["resource_id"],
            resource_type=row["resource_type"],
            provider=row["provider"],
            band=Severity(row["band"]),
            score=row["score"],
            title=row["title"],
            state=FindingState(row["state"]),
            verification_status=VerificationStatus(row["verification_status"]),
            owner=row["owner"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            due_date=_opt_dt(row["due_date"]),
            closed_at=_opt_dt(row["closed_at"]),
            last_scan_id=row["last_scan_id"],
            data=json.loads(row["data"]),
        )
