"""Ground truth recall on the insecure testbed and zero findings on the secure one.

Inputs:
- testbed/ground-truth.yaml: list of {rule_id, resource_type, resource_name, provider, note}
  (a top-level mapping with a `findings` or `ground_truth` list is accepted too).
- testbed/recorded/insecure*.json and testbed/recorded/secure*.json: recorded collector
  output, each a JSON list of Resource.to_dict() objects.
The tests skip with the reason when an input is missing.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from cspm.contracts import Finding, Provider, Resource, ScanContext, ScanMode
from cspm.engine import run_rules

ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH = ROOT / "testbed" / "ground-truth.yaml"
RECORDED = Path(os.environ.get("CSPM_RECORDED_DIR", ROOT / "testbed" / "recorded"))
ACCOUNT_TYPES = {"aws.iam.account", "aws.cloudtrail.account", "aws.ec2.region_settings"}
NAME_KEYS = ("name", "identifier", "group_id", "volume_id", "key_id", "domain")
# Testbed keys were made on 2026-11-23. Scanning 120 days later lets the key age rule fire, matching --now +120d.
SCAN_TIME = datetime(2027, 3, 23, tzinfo=UTC)


def load_ground_truth(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("findings") or data.get("ground_truth") or []
    return [dict(row) for row in data]


def load_resources(paths: Iterable[Path]) -> list[Resource]:
    out = []
    for path in paths:
        for raw in json.loads(path.read_text(encoding="utf-8")):
            out.append(
                Resource(
                    id=raw["id"],
                    type=raw["type"],
                    provider=Provider(raw["provider"]),
                    region=raw.get("region", "global"),
                    config=raw.get("config", {}),
                    tags=raw.get("tags", {}),
                )
            )
    return out


def resource_names(finding: Finding, resources: dict[str, Resource]) -> set[str]:
    names = {finding.resource_id, finding.resource_id.rsplit("/", 1)[-1], finding.resource_id.rsplit(":", 1)[-1]}
    res = resources.get(finding.resource_id)
    if res is not None:
        names |= {str(res.config[k]) for k in NAME_KEYS if res.config.get(k)}
        if res.tags.get("Name"):
            names.add(str(res.tags["Name"]))
    return names


def missed(truth: Sequence[dict[str, Any]], findings: Sequence[Finding], resources: Sequence[Resource]) -> list[str]:
    """Ground truth rows with no matching finding (rule, type and resource name)."""
    by_id = {r.id: r for r in resources}
    gaps = []
    for row in truth:
        hit = False
        for f in findings:
            if f.rule_id != row["rule_id"] or f.resource_type != row["resource_type"]:
                continue
            if row["resource_type"] in ACCOUNT_TYPES or str(row["resource_name"]) in resource_names(f, by_id):
                hit = True
                break
        if not hit:
            gaps.append(f"{row['rule_id']} on {row['resource_type']} {row['resource_name']}")
    return gaps


def _scan(resources: Sequence[Resource]) -> list[Finding]:
    return run_rules(resources, ScanContext(now=SCAN_TIME, mode=ScanMode.EMULATOR))


def _need(paths: list[Path], what: str) -> list[Path]:
    if not paths:
        pytest.skip(f"no recorded collector output for the {what} testbed in {RECORDED}")
    return paths


def test_recall_on_insecure_testbed() -> None:
    if not GROUND_TRUTH.exists():
        pytest.skip(f"{GROUND_TRUTH.relative_to(ROOT)} not present")
    truth = load_ground_truth(GROUND_TRUTH)
    resources = load_resources(_need(sorted(RECORDED.glob("insecure*.json")), "insecure"))
    findings = _scan(resources)
    gaps = missed(truth, findings, resources)
    assert not gaps, f"recall {len(truth) - len(gaps)}/{len(truth)}; missed: {gaps}"
    extra = len(findings) - len(truth)
    assert extra == 0, f"{len(findings)} findings for {len(truth)} seeded issues: {sorted(f.rule_id for f in findings)}"


def test_secure_testbed_has_no_findings() -> None:
    resources = load_resources(_need(sorted(RECORDED.glob("secure*.json")), "secure"))
    findings = _scan(resources)
    assert not findings, [f"{f.rule_id} {f.resource_id}" for f in findings]


def test_matcher_on_synthetic_inputs(tmp_path: Path) -> None:
    """Keeps the matching logic honest while the real inputs are absent."""
    gt = tmp_path / "gt.yaml"
    gt.write_text(
        yaml.safe_dump(
            {
                "findings": [
                    {
                        "rule_id": "ASSAY-EC2-006",
                        "resource_type": "aws.ec2.region_settings",
                        "resource_name": "account",
                        "provider": "aws",
                        "note": "",
                    },
                    {
                        "rule_id": "ASSAY-RDS-001",
                        "resource_type": "aws.rds.instance",
                        "resource_name": "orders-db",
                        "provider": "aws",
                        "note": "",
                    },
                    {
                        "rule_id": "ASSAY-RDS-002",
                        "resource_type": "aws.rds.instance",
                        "resource_name": "other-db",
                        "provider": "aws",
                        "note": "",
                    },
                ]
            }
        )
    )
    rec = tmp_path / "insecure.json"
    rec.write_text(
        json.dumps(
            [
                Resource(
                    "111:us-east-1:aws.ec2.region_settings",
                    "aws.ec2.region_settings",
                    Provider.AWS,
                    "us-east-1",
                    {"ebs_encryption_by_default": False},
                ).to_dict(),
                Resource(
                    "arn:aws:rds:us-east-1:111:db:orders-db",
                    "aws.rds.instance",
                    Provider.AWS,
                    "us-east-1",
                    {
                        "identifier": "orders-db",
                        "engine": "mysql",
                        "publicly_accessible": True,
                        "storage_encrypted": True,
                        "security_group_ids": [],
                    },
                ).to_dict(),
            ]
        )
    )
    resources = load_resources([rec])
    gaps = missed(load_ground_truth(gt), _scan(resources), resources)
    assert gaps == ["ASSAY-RDS-002 on aws.rds.instance other-db"]
