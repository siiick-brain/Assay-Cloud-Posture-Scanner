"""Findings report dict: build from Finding objects and validate against the frozen schema."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime
from importlib import resources
from typing import Any

import jsonschema

from cspm.contracts import (
    SCHEMA_VERSION,
    ControlRef,
    Finding,
    FindingState,
    Severity,
    Source,
    VerificationStatus,
)

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def load_schema() -> dict[str, Any]:
    """Return the frozen findings schema."""
    text = resources.files("cspm.contracts").joinpath("findings.schema.json").read_text(encoding="utf-8")
    schema: dict[str, Any] = json.loads(text)
    return schema


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def finding_to_dict(f: Finding) -> dict[str, Any]:
    """Serialize one Finding into the schema shape."""
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "source": f.source.value,
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "provider": f.provider,
        "region": f.region,
        "title": f.title,
        "severity_base": f.severity_base.value,
        "score": f.score,
        "band": f.band.value,
        "rationale": f.rationale,
        "impact": f.impact,
        "remediation": f.remediation,
        "evidence": dict(f.evidence),
        "controls": [{"framework": c.framework, "control_id": c.control_id} for c in f.controls],
        "references": list(f.references),
        "state": f.state.value,
        "verification_status": f.verification_status.value,
        "owner": f.owner,
        "first_seen": _iso(f.first_seen),
        "last_seen": _iso(f.last_seen),
        "due_date": _iso(f.due_date),
        "scan_id": f.scan_id,
    }


def finding_from_dict(d: Mapping[str, Any]) -> Finding:
    """Rebuild a Finding from its schema shape; the id is recomputed from the identity fields."""
    return Finding(
        rule_id=d["rule_id"],
        resource_id=d["resource_id"],
        resource_type=d["resource_type"],
        provider=d["provider"],
        region=d["region"],
        title=d["title"],
        severity_base=Severity(d["severity_base"]),
        rationale=d["rationale"],
        impact=d["impact"],
        remediation=d["remediation"],
        evidence=dict(d["evidence"]),
        source=Source(d["source"]),
        score=float(d["score"]),
        band=Severity(d["band"]),
        controls=[ControlRef(c["framework"], c["control_id"]) for c in d["controls"]],
        references=list(d["references"]),
        state=FindingState(d["state"]),
        verification_status=VerificationStatus(d["verification_status"]),
        owner=d.get("owner"),
        first_seen=_dt(d.get("first_seen")),
        last_seen=_dt(d.get("last_seen")),
        due_date=_dt(d.get("due_date")),
        scan_id=d.get("scan_id"),
    )


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def build_report(scan: Mapping[str, Any], findings: Iterable[Finding]) -> dict[str, Any]:
    """Wrap scan metadata and findings into a report dict."""
    return {
        "schema_version": SCHEMA_VERSION,
        "scan": dict(scan),
        "findings": [finding_to_dict(f) for f in findings],
    }


def validate_report(report: Mapping[str, Any]) -> None:
    """Raise jsonschema.ValidationError when the report does not match the schema."""
    validator = jsonschema.Draft202012Validator(load_schema(), format_checker=jsonschema.FormatChecker())
    validator.validate(report)


def sorted_findings(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Findings ordered by band, then score descending, then id for stable output."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    items: list[dict[str, Any]] = list(report.get("findings", []))
    return sorted(items, key=lambda f: (rank.get(f["band"], 99), -float(f["score"]), f["id"]))


def band_counts(report: Mapping[str, Any]) -> dict[str, int]:
    """Count findings per band, every band present."""
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for f in report.get("findings", []):
        counts[f["band"]] = counts.get(f["band"], 0) + 1
    return counts
