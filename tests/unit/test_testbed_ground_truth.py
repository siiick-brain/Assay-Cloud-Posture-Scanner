"""Checks testbed/ground-truth.yaml against the Terraform stacks, the Azure fixtures and the recorded scans."""

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from cspm.contracts import RULE_ID_SET, RULE_IDS

ROOT = Path(__file__).resolve().parents[2]
TESTBED = ROOT / "testbed"
DOC: dict[str, Any] = yaml.safe_load((TESTBED / "ground-truth.yaml").read_text(encoding="utf-8"))
TRUTH: list[dict[str, Any]] = DOC["ground_truth"]
RULE_TYPES = {r.id: r.resource_type for r in RULE_IDS}
ACCOUNT_TYPES = {"aws.iam.account", "aws.cloudtrail.account"}
# Resource types and the Terraform resource that creates them.
TF_TYPES = {
    "aws.s3.bucket": "aws_s3_bucket",
    "aws.ec2.security_group": "aws_security_group",
    "aws.ec2.volume": "aws_ebs_volume",
    "aws.iam.policy": "aws_iam_policy",
    "aws.iam.user": "aws_iam_user",
    "aws.kms.key": "aws_kms_key",
}
AZURE_TYPES = {
    "azure.storage.container": "Microsoft.Storage/storageAccounts/blobServices/containers",
    "azure.network.nsg": "Microsoft.Network/networkSecurityGroups",
    "azure.keyvault.vault": "Microsoft.KeyVault/vaults",
    "azure.compute.disk": "Microsoft.Compute/disks",
    "azure.storage.account": "Microsoft.Storage/storageAccounts",
}


def _tf_names(stack: str) -> dict[str, set[str]]:
    """Map Terraform resource type to the names or Name tags it declares, with the local prefix filled in."""
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted((TESTBED / stack).glob("*.tf")))
    prefix = re.search(r'prefix\s*=\s*"([^"]+)"', text)
    assert prefix
    text = text.replace("${local.prefix}", prefix.group(1))
    names: dict[str, set[str]] = {}
    for block in re.finditer(r'^resource "(\w+)" "\w+" \{(.*?)^\}', text, re.S | re.M):
        rtype, body = block.group(1), block.group(2)
        found = re.findall(r'^\s*(?:bucket|name)\s*=\s*"([^"]+)"', body, re.M)
        found += re.findall(r'Name\s*=\s*"([^"]+)"', body)
        names.setdefault(rtype, set()).update(found)
    return names


def _tf_region(stack: str) -> str:
    match = re.search(r'region\s*=\s*"([^"]+)"', (TESTBED / stack / "provider.tf").read_text(encoding="utf-8"))
    assert match
    return match.group(1)


def _azure(stack: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for f in sorted((TESTBED / "azure-fixtures" / stack).glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        assert data["synthetic"] is True, f
        items += data["resources"]
    return items


def test_expected_count_matches_aws_entries() -> None:
    assert set(DOC) == {"expected_finding_count", "ground_truth"}
    assert DOC["expected_finding_count"] == sum(1 for r in TRUTH if r["provider"] == "aws")


def test_ground_truth_shape() -> None:
    assert isinstance(TRUTH, list)
    assert TRUTH
    for row in TRUTH:
        assert set(row) == {"rule_id", "resource_type", "resource_name", "provider", "note"}, row
        assert row["rule_id"] in RULE_ID_SET, row
        assert RULE_TYPES[row["rule_id"]] == row["resource_type"], row
        assert row["provider"] == row["resource_type"].split(".")[0]
        assert row["note"]


def test_no_duplicate_entries() -> None:
    keys = Counter((r["rule_id"], r["resource_type"], r["resource_name"]) for r in TRUTH)
    assert [k for k, n in keys.items() if n > 1] == []


@pytest.mark.parametrize("row", [r for r in TRUTH if r["provider"] == "aws"], ids=lambda r: r["rule_id"])
def test_aws_entry_exists_in_insecure_terraform(row: dict[str, Any]) -> None:
    rtype = row["resource_type"]
    if rtype in ACCOUNT_TYPES:
        assert row["resource_name"] == "account"
    elif rtype == "aws.ec2.region_settings":
        assert row["resource_name"] == _tf_region("insecure")
    else:
        assert row["resource_name"] in _tf_names("insecure").get(TF_TYPES[rtype], set()), row


@pytest.mark.parametrize("row", [r for r in TRUTH if r["provider"] == "azure"], ids=lambda r: r["rule_id"])
def test_azure_entry_exists_in_insecure_fixtures(row: dict[str, Any]) -> None:
    matches = [i for i in _azure("insecure") if i["name"] == row["resource_name"]]
    assert len(matches) == 1, row
    assert matches[0]["type"] == AZURE_TYPES[row["resource_type"]]


def test_seeded_values_present() -> None:
    insecure = (TESTBED / "insecure" / "main.tf").read_text(encoding="utf-8")
    for needle in (
        'acl    = "public-read"',
        'cidr_blocks = ["0.0.0.0/0"]',
        "from_port   = 22",
        "from_port   = 5432",
        "encrypted         = false",
        "enable_key_rotation     = false",
        'Action = "*"',
        'Action = "s3:*"',
        "aws_iam_user_login_profile",
        "aws_iam_access_key",
    ):
        assert needle in insecure, needle
    for absent in ("aws_cloudtrail", "aws_iam_account_password_policy", "aws_ebs_encryption_by_default"):
        assert absent not in insecure, absent


def test_secure_stack_fixes_every_seed() -> None:
    secure = (TESTBED / "secure" / "main.tf").read_text(encoding="utf-8")
    for needle in (
        "aws_cloudtrail",
        "is_multi_region_trail         = true",
        "enable_log_file_validation    = true",
        "aws_iam_account_password_policy",
        "aws_ebs_encryption_by_default",
        "enable_key_rotation     = true",
        "encrypted         = true",
    ):
        assert needle in secure, needle
    for absent in ("0.0.0.0/0", "public-read", "aws_iam_user_login_profile", "aws_iam_access_key", '"*"'):
        assert absent not in secure, absent
    named = [r for r in TRUTH if r["provider"] == "aws" and r["resource_type"] in TF_TYPES]
    assert not any(r["resource_name"] in secure for r in named)


def test_secure_fixtures_are_clean() -> None:
    names = {i["name"] for i in _azure("secure")}
    assert not names & {r["resource_name"] for r in TRUTH}
    for item in _azure("secure"):
        props = item.get("properties", {})
        assert props.get("publicAccess", "None") == "None"
        assert props.get("enablePurgeProtection", True) is True
        for rule in props.get("securityRules", []):
            assert rule["properties"]["sourceAddressPrefix"] != "*"


def test_every_resource_tagged() -> None:
    for stack in ("insecure", "secure"):
        text = (TESTBED / stack / "main.tf").read_text(encoding="utf-8")
        blocks = re.findall(r'^resource "(\w+)" "\w+" \{(.*?)^\}', text, re.S | re.M)
        for rtype, body in blocks:
            if rtype in TF_TYPES.values() or rtype == "aws_vpc":
                assert "criticality" in body and "data_sensitivity" in body, (stack, rtype)
        for item in _azure(stack):
            assert {"criticality", "data_sensitivity"} <= set(item["tags"]), item["name"]


def _recorded(stack: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in sorted((TESTBED / "recorded").glob(f"{stack}*.json")):
        out += json.loads(f.read_text(encoding="utf-8"))
    return out


def _matches(res: dict[str, Any], row: dict[str, Any]) -> bool:
    if res["type"] != row["resource_type"]:
        return False
    name = row["resource_name"]
    if row["resource_type"] in ACCOUNT_TYPES:
        return True
    if row["resource_type"] == "aws.ec2.region_settings":
        return bool(res["region"] == name)
    return name in {res["config"].get("name"), res["tags"].get("Name")}


@pytest.mark.parametrize("row", TRUTH, ids=lambda r: f"{r['rule_id']}-{r['resource_name']}")
def test_recorded_insecure_scan_has_every_seeded_resource(row: dict[str, Any]) -> None:
    assert any(_matches(res, row) for res in _recorded("insecure")), row


def test_recorded_scans_are_resource_dicts() -> None:
    for stack in ("insecure", "secure"):
        rows = _recorded(stack)
        assert rows, stack
        for res in rows:
            assert set(res) == {"id", "type", "provider", "region", "config", "tags"}
    named = [r for r in TRUTH if r["resource_type"] in TF_TYPES or r["provider"] == "azure"]
    assert not any(_matches(res, row) for res in _recorded("secure") for row in named)
