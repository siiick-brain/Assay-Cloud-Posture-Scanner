"""Finding model and lifecycle enums. Frozen at contracts-v1."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "1.0.0"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingState(StrEnum):
    NEW = "new"
    OPEN = "open"
    ASSIGNED = "assigned"
    FIXED_CLAIMED = "fixed_claimed"
    VERIFIED_CLOSED = "verified_closed"
    REOPENED = "reopened"


class VerificationStatus(StrEnum):
    """How strongly a closure is backed. Depends on scan mode, not on the finding."""

    VERIFIED = "verified"
    OBSERVED_UNVERIFIED = "observed_unverified"
    NOT_VERIFIED = "not_verified"


class Source(StrEnum):
    ASSAY = "assay"
    TRIVY = "trivy"
    PROWLER = "prowler"
    CHECKOV = "checkov"
    OPENSCAP = "openscap"


class ScanMode(StrEnum):
    EMULATOR = "emulator"
    FIXTURE = "fixture"
    LIVE = "live"


@dataclass(frozen=True, slots=True)
class ControlRef:
    framework: str
    control_id: str


@dataclass(slots=True)
class Finding:
    """One rule violation on one resource, with the explanation contract fields."""

    rule_id: str
    resource_id: str
    resource_type: str
    provider: str
    region: str
    title: str
    severity_base: Severity
    rationale: str
    impact: str
    remediation: str
    evidence: dict[str, Any]
    source: Source = Source.ASSAY
    score: float = 0.0
    band: Severity = Severity.INFO
    controls: list[ControlRef] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    state: FindingState = FindingState.NEW
    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    owner: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    due_date: datetime | None = None
    scan_id: str | None = None

    @property
    def id(self) -> str:
        """Stable across scans so the store can match the same issue again."""
        raw = f"{self.source.value}|{self.rule_id}|{self.resource_id}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]


def verification_for(mode: ScanMode) -> VerificationStatus:
    """Map the scan mode of a confirming rescan to the verification status it earns."""
    if mode is ScanMode.LIVE:
        return VerificationStatus.OBSERVED_UNVERIFIED
    return VerificationStatus.VERIFIED
