import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import yaml

from cspm.contracts import (
    RESOURCE_TYPES,
    RULE_ID_SET,
    RULE_IDS,
    Finding,
    Provider,
    Resource,
    ScanMode,
    Severity,
    VerificationStatus,
    verification_for,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "cspm/contracts/findings.schema.json").read_text())
ALLOWLIST = yaml.safe_load((ROOT / "cspm/live/allowlist.yaml").read_text())


def test_rule_ids_unique_and_enough() -> None:
    assert len(RULE_IDS) >= 25
    assert len(RULE_ID_SET) == len(RULE_IDS)


def test_rule_resource_types_known() -> None:
    assert all(r.resource_type in RESOURCE_TYPES for r in RULE_IDS)


def test_finding_id_is_stable() -> None:
    f = _finding()
    assert f.id == _finding().id
    assert len(f.id) == 16


def test_verification_depends_on_mode() -> None:
    assert verification_for(ScanMode.EMULATOR) is VerificationStatus.VERIFIED
    assert verification_for(ScanMode.FIXTURE) is VerificationStatus.VERIFIED
    assert verification_for(ScanMode.LIVE) is VerificationStatus.OBSERVED_UNVERIFIED


def test_sample_report_validates() -> None:
    f = _finding()
    report = {
        "schema_version": "1.0.0",
        "scan": {
            "scan_id": "s1",
            "started_at": "2026-11-23T00:00:00Z",
            "finished_at": "2026-11-23T00:00:01Z",
            "mode": "emulator",
            "providers": ["aws"],
            "resource_count": 1,
            "tool_version": "0.1.0",
        },
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "source": f.source.value,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "provider": f.provider,
                "region": f.region,
                "title": f.title,
                "severity_base": f.severity_base.value,
                "score": 7.5,
                "band": "high",
                "rationale": f.rationale,
                "impact": f.impact,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "controls": [],
                "references": [],
                "state": f.state.value,
                "verification_status": f.verification_status.value,
            }
        ],
    }
    jsonschema.validate(report, SCHEMA)


def test_allowlist_is_read_only() -> None:
    prefixes = tuple(ALLOWLIST["allowed_prefixes"])
    for service, ops in ALLOWLIST["operations"].items():
        for op in ops:
            assert op.startswith(prefixes), f"{service}:{op}"
            assert f"{service}:{op}" not in ALLOWLIST["deny"]


def test_resource_round_trip() -> None:
    r = Resource("arn:aws:s3:::b", "aws.s3.bucket", Provider.AWS, "us-east-1", {"name": "b"}, {"criticality": "high"})
    assert r.to_dict()["provider"] == "aws"


def _finding() -> Finding:
    return Finding(
        rule_id="ASSAY-S3-001",
        resource_id="arn:aws:s3:::b",
        resource_type="aws.s3.bucket",
        provider="aws",
        region="us-east-1",
        title="Bucket readable by the public",
        severity_base=Severity.HIGH,
        rationale="Public buckets leak data.",
        impact="Anyone can list and read objects.",
        remediation="Turn on Block Public Access.",
        evidence={"acl": "public-read"},
        first_seen=datetime(2026, 11, 23, tzinfo=UTC),
    )
