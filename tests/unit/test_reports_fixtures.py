"""Synthetic findings shared by the report and store tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cspm.contracts import ControlRef, Finding, Severity

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def make_finding(
    rule_id: str = "ASSAY-S3-001",
    resource_id: str = "arn:aws:s3:::public-data",
    band: Severity = Severity.HIGH,
    score: float = 8.1,
    **extra: Any,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        resource_id=resource_id,
        resource_type=extra.pop("resource_type", "aws.s3.bucket"),
        provider=extra.pop("provider", "aws"),
        region=extra.pop("region", "us-east-1"),
        title=extra.pop("title", "Bucket readable by the public"),
        severity_base=band,
        rationale="Public buckets leak data.",
        impact="Anyone on the internet can read objects.",
        remediation="Turn on Block Public Access.",
        evidence=extra.pop("evidence", {"acl": "public-read"}),
        score=score,
        band=band,
        controls=extra.pop("controls", [ControlRef("nist-800-53", "AC-3"), ControlRef("iso27001", "A.8.3")]),
        references=extra.pop("references", ["https://docs.aws.amazon.com/s3/"]),
        **extra,
    )


def scan_meta(scan_id: str = "scan-1", mode: str = "emulator") -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "started_at": "2026-11-01T12:00:00+00:00",
        "finished_at": "2026-11-01T12:00:05+00:00",
        "mode": mode,
        "providers": ["aws"],
        "resource_count": 12,
        "tool_version": "0.1.0",
    }
