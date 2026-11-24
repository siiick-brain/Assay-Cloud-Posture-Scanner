"""One positive and one negative case per rule, built by hand from the contract config keys."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from cspm.contracts import RULE_IDS, Provider, Resource, Rule, ScanContext, ScanMode
from rules import ALL_RULES, RULES_BY_ID, RULES_BY_TYPE, rules_for_type

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
CTX = ScanContext(now=NOW, mode=ScanMode.FIXTURE)

DEFAULTS: dict[str, dict[str, Any]] = {
    "aws.s3.bucket": {
        "name": "b",
        "acl_grants": [],
        "policy": None,
        "policy_is_public": False,
        "public_access_block": dict.fromkeys(
            ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"), True
        ),
        "encryption": {"algorithm": "aws:kms", "kms_key_id": "k"},
        "versioning": "Enabled",
        "logging_enabled": True,
    },
    "aws.ec2.security_group": {"group_id": "sg-1", "name": "web", "vpc_id": "vpc-1", "ingress": []},
    "aws.ec2.volume": {"volume_id": "vol-1", "encrypted": True, "kms_key_id": "k", "attached_instance_ids": []},
    "aws.ec2.region_settings": {"ebs_encryption_by_default": True},
    "aws.rds.instance": {
        "identifier": "db",
        "engine": "postgres",
        "publicly_accessible": False,
        "storage_encrypted": True,
        "security_group_ids": [],
    },
    "aws.iam.policy": {
        "name": "p",
        "arn": "arn:aws:iam::111122223333:policy/p",
        "document": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        },
        "attached": True,
        "aws_managed": False,
    },
    "aws.iam.user": {
        "name": "u",
        "has_console_password": True,
        "mfa_devices": 1,
        "access_keys": [],
        "attached_policy_arns": [],
        "inline_policies": [],
    },
    "aws.iam.role": {
        "name": "r",
        "trust_policy": {
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ]
        },
        "attached_policy_arns": [],
        "inline_policies": [],
    },
    "aws.iam.account": {
        "root_access_keys_present": False,
        "root_mfa_enabled": True,
        "password_policy": {
            "minimum_length": 14,
            "require_symbols": True,
            "require_numbers": True,
            "require_uppercase": True,
            "require_lowercase": True,
            "max_age_days": None,
        },
    },
    "aws.cloudtrail.trail": {
        "name": "t",
        "is_multi_region": True,
        "is_logging": True,
        "log_file_validation": True,
        "home_region": "us-east-1",
    },
    "aws.cloudtrail.account": {"trail_names": ["t"], "has_logging_multi_region_trail": True},
    "aws.kms.key": {
        "key_id": "k1",
        "manager": "CUSTOMER",
        "state": "Enabled",
        "rotation_enabled": True,
        "policy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ]
        },
        "key_spec": "SYMMETRIC_DEFAULT",
    },
    "aws.secretsmanager.secret": {
        "name": "s",
        "rotation_enabled": True,
        "last_rotated": "2026-11-01T00:00:00Z",
        "created": "2025-01-01T00:00:00Z",
    },
    "aws.acm.certificate": {
        "domain": "example.test",
        "not_after": "2027-06-01T00:00:00Z",
        "key_algorithm": "RSA_2048",
        "signature_algorithm": "SHA256WITHRSA",
        "status": "ISSUED",
    },
    "azure.storage.account": {
        "name": "sa",
        "https_only": True,
        "min_tls_version": "TLS1_2",
        "allow_blob_public_access": False,
    },
    "azure.storage.container": {"name": "c", "account": "sa", "public_access": "None"},
    "azure.network.nsg": {
        "name": "nsg",
        "security_rules": [
            {
                "name": "https",
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "source_address_prefix": "*",
                "destination_port_range": "443",
                "priority": 100,
            }
        ],
    },
    "azure.keyvault.vault": {"name": "kv", "purge_protection": True, "soft_delete": True},
    "azure.compute.disk": {
        "name": "d",
        "encryption_type": "EncryptionAtRestWithPlatformKey",
        "encryption_enabled": True,
    },
}


def make(rtype: str, tags: dict[str, str] | None = None, **overrides: Any) -> Resource:
    """A clean resource of `rtype` with selected config keys replaced."""
    provider = Provider.AZURE if rtype.startswith("azure.") else Provider.AWS
    region = "global" if rtype.startswith("aws.iam.") else "us-east-1"
    config = {**DEFAULTS[rtype], **overrides}
    return Resource(id=f"{rtype}/test", type=rtype, provider=provider, region=region, config=config, tags=tags or {})


def sg_rule(
    protocol: str = "tcp",
    low: int | None = 22,
    high: int | None = 22,
    cidrs: tuple[str, ...] = ("0.0.0.0/0",),
    v6: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {"protocol": protocol, "from_port": low, "to_port": high, "cidrs": list(cidrs), "ipv6_cidrs": list(v6)}


def doc(*stmts: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(stmts)}


ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}
OPEN_PRINCIPAL = {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}

# rule_id -> (violating overrides, clean overrides); clean {} means the defaults pass.
CASES: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "ASSAY-S3-001": (
        {
            "acl_grants": [{"grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"}],
            "public_access_block": {},
        },
        {"acl_grants": [{"grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"}]},
    ),
    "ASSAY-S3-002": ({"public_access_block": {"block_public_acls": True}}, {}),
    "ASSAY-S3-003": ({"encryption": None}, {}),
    "ASSAY-S3-004": ({"versioning": "Suspended"}, {}),
    "ASSAY-S3-005": ({"logging_enabled": False}, {}),
    "ASSAY-EC2-001": ({"ingress": [sg_rule()]}, {"ingress": [sg_rule(cidrs=("10.0.0.0/8",))]}),
    "ASSAY-EC2-002": ({"ingress": [sg_rule(low=3389, high=3389)]}, {"ingress": [sg_rule(low=443, high=443)]}),
    "ASSAY-EC2-003": ({"ingress": [sg_rule(low=5432, high=5432)]}, {"ingress": [sg_rule(low=443, high=443)]}),
    "ASSAY-EC2-004": (
        {"ingress": [sg_rule(protocol="-1", low=None, high=None)]},
        {"ingress": [sg_rule(low=443, high=443)]},
    ),
    "ASSAY-EC2-005": ({"encrypted": False, "kms_key_id": None}, {}),
    "ASSAY-EC2-006": ({"ebs_encryption_by_default": False}, {}),
    "ASSAY-RDS-001": ({"publicly_accessible": True}, {}),
    "ASSAY-RDS-002": ({"storage_encrypted": False}, {}),
    "ASSAY-IAM-001": ({"document": doc(ADMIN)}, {}),
    "ASSAY-IAM-002": ({"document": doc({"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"})}, {}),
    "ASSAY-IAM-003": (
        {"attached_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
        {"attached_policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]},
    ),
    "ASSAY-IAM-004": ({"mfa_devices": 0}, {}),
    "ASSAY-IAM-005": (
        {"access_keys": [{"key_id_suffix": "WXYZ", "status": "Active", "created": "2026-01-01T00:00:00Z"}]},
        {"access_keys": [{"key_id_suffix": "WXYZ", "status": "Active", "created": "2026-11-01T00:00:00Z"}]},
    ),
    "ASSAY-IAM-006": ({"trust_policy": doc(OPEN_PRINCIPAL)}, {}),
    "ASSAY-IAM-007": ({"root_access_keys_present": True}, {}),
    "ASSAY-IAM-008": ({"password_policy": None}, {}),
    "ASSAY-LOG-001": ({"has_logging_multi_region_trail": False, "trail_names": []}, {}),
    "ASSAY-LOG-002": ({"log_file_validation": False}, {}),
    "ASSAY-KMS-001": ({"rotation_enabled": False}, {}),
    "ASSAY-KMS-002": (
        {"policy": doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:*", "Resource": "*"})},
        {},
    ),
    "ASSAY-SEC-001": ({"last_rotated": "2026-06-01T00:00:00Z"}, {}),
    "ASSAY-ACM-001": ({"not_after": "2026-12-10T00:00:00Z"}, {}),
    "ASSAY-ACM-002": ({"key_algorithm": "RSA_1024"}, {}),
    "ASSAY-AZ-STG-001": ({"public_access": "Container"}, {}),
    "ASSAY-AZ-STG-002": ({"https_only": False}, {}),
    "ASSAY-AZ-NSG-001": (
        {
            "security_rules": [
                {**DEFAULTS["azure.network.nsg"]["security_rules"][0], "name": "any", "destination_port_range": "*"}
            ]
        },
        {},
    ),
    "ASSAY-AZ-KV-001": ({"purge_protection": False}, {}),
    "ASSAY-AZ-DSK-001": ({"encryption_enabled": False, "encryption_type": None}, {}),
}


def _rtype(rule_id: str) -> str:
    return RULES_BY_ID[rule_id].meta.resource_types[0]


def run(rule_id: str, resource: Resource, ctx: ScanContext = CTX) -> list[Any]:
    return RULES_BY_ID[rule_id].evaluate(resource, ctx)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_positive(rule_id: str) -> None:
    violations = run(rule_id, make(_rtype(rule_id), **CASES[rule_id][0]))
    assert len(violations) >= 1
    assert all(v.exposure in ("none", "internal", "internet") for v in violations)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_negative(rule_id: str) -> None:
    assert run(rule_id, make(_rtype(rule_id), **CASES[rule_id][1])) == []


def test_every_rule_has_cases() -> None:
    assert set(CASES) == {r.id for r in RULE_IDS}


def test_registry_matches_frozen_list() -> None:
    frozen = {r.id: r for r in RULE_IDS}
    assert len(ALL_RULES) == len(frozen) == 33
    for rule in ALL_RULES:
        assert isinstance(rule, Rule)
        spec = frozen[rule.meta.id]
        assert rule.meta.severity_base == spec.severity_base
        assert rule.meta.resource_types == (spec.resource_type,)
        assert rule.meta.title == spec.summary
        assert rule.meta.rationale and rule.meta.impact and rule.meta.remediation
        assert rule in rules_for_type(spec.resource_type)
    assert sum(len(v) for v in RULES_BY_TYPE.values()) == 33
    assert rules_for_type("aws.unknown") == ()


def test_clean_defaults_pass_every_rule() -> None:
    for rule in ALL_RULES:
        assert rule.evaluate(make(rule.meta.resource_types[0]), CTX) == [], rule.meta.id
