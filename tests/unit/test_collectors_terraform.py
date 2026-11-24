import json
from pathlib import Path
from typing import Any

import pytest

from cspm.collectors import collect
from cspm.collectors.terraform_plan import resources_from_plan
from cspm.contracts import Provider, Resource, ScanMode

ROOT = Path(__file__).resolve().parents[2]
PLANS = ROOT / "testbed" / "plans"


def _plan(resources: list[dict[str, Any]], refs: dict[str, dict[str, list[str]]] | None = None) -> dict[str, Any]:
    conf = [
        {"address": addr, "expressions": {k: {"references": v} for k, v in exprs.items()}}
        for addr, exprs in (refs or {}).items()
    ]
    return {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": r["address"], "type": r["address"].split(".")[0], **r} for r in resources[:1]
                ],
                "child_modules": [{"resources": [{"type": r["address"].split(".")[0], **r} for r in resources[1:]]}],
            }
        },
        "configuration": {
            "provider_config": {"aws": {"expressions": {"region": {"constant_value": "eu-west-1"}}}},
            "root_module": {"resources": conf},
        },
    }


def _types(rs: list[Resource]) -> dict[str, Resource]:
    return {r.id: r for r in rs}


def test_insecure_plan_file() -> None:
    rs = collect(Provider.TERRAFORM, mode=ScanMode.FIXTURE, source=str(PLANS / "insecure.plan.json"))
    by = _types(rs)
    assert all(r.provider is Provider.TERRAFORM for r in rs)
    pub = by["aws_s3_bucket.public"]
    assert pub.region == "us-east-1"
    assert pub.config["acl_grants"] == [
        {"grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"}
    ]
    assert not any(pub.config["public_access_block"].values())
    assert pub.config["versioning"] == "Enabled"
    assert pub.config["logging_enabled"] is True
    unenc = by["aws_s3_bucket.unencrypted"]
    assert unenc.config["encryption"] is None
    assert unenc.config["versioning"] == "Disabled"
    assert all(unenc.config["public_access_block"].values())
    sg = by["aws_security_group.open"]
    assert sorted(i["from_port"] for i in sg.config["ingress"]) == [22, 5432]
    assert by["aws_ebs_volume.data"].config["encrypted"] is False
    assert by["aws_iam_policy.admin_wildcard"].config["attached"] is True
    assert by["aws_iam_policy.s3_wildcard"].config["document"]["Statement"][0]["Action"] == "s3:*"
    user = by["aws_iam_user.dev"]
    assert user.config["has_console_password"] is True
    assert len(user.config["access_keys"]) == 1
    assert by["aws_kms_key.data"].config["rotation_enabled"] is False
    assert by["aws_kms_key.data"].tags["criticality"] == "high"


def test_secure_plan_file() -> None:
    rs = collect(Provider.TERRAFORM, mode=ScanMode.FIXTURE, source=str(PLANS / "secure.plan.json"))
    by = _types(rs)
    assert by["aws_kms_key.data"].config["rotation_enabled"] is True
    assert by["aws_ebs_volume.data"].config["encrypted"] is True
    assert by["aws_ebs_encryption_by_default.on"].config == {"ebs_encryption_by_default": True}
    trail = by["aws_cloudtrail.main"]
    assert trail.config["is_multi_region"] is True
    assert trail.config["log_file_validation"] is True
    assert by["terraform:cloudtrail-account"].config["has_logging_multi_region_trail"] is True
    assert by["aws_iam_account_password_policy.strict"].config["password_policy"]["minimum_length"] == 14
    data = by["aws_s3_bucket.data"]
    assert data.config["encryption"]["algorithm"] == "aws:kms"
    # The trail policy references the bucket ARN, so it is unknown until apply.
    assert by["aws_s3_bucket.trail"].config["policy"] is None
    assert by["aws_s3_bucket.trail"].config["policy_is_public"] is False


def test_linking_by_reference_and_module_walk() -> None:
    policy = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]})
    plan = _plan(
        [
            {"address": "aws_s3_bucket.b", "values": {"bucket": None, "tags": {"criticality": "low"}}},
            {"address": "aws_s3_bucket_policy.b", "values": {"bucket": None, "policy": policy}},
            {
                "address": "aws_s3_bucket_acl.b",
                "values": {
                    "bucket": None,
                    "acl": None,
                    "access_control_policy": [
                        {
                            "grant": [
                                {
                                    "grantee": [{"uri": "http://acs.amazonaws.com/groups/global/AllUsers"}],
                                    "permission": "READ",
                                }
                            ]
                        }
                    ],
                },
            },
            {"address": "aws_security_group.sg", "values": {"name": "sg", "ingress": []}},
            {
                "address": "aws_security_group_rule.r",
                "values": {"type": "ingress", "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]},
            },
            {"address": "aws_security_group_rule.e", "values": {"type": "egress", "protocol": "-1"}},
            {
                "address": "aws_vpc_security_group_ingress_rule.v",
                "values": {"ip_protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ipv6": "::/0"},
            },
        ],
        {
            "aws_s3_bucket_policy.b": {"bucket": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]},
            "aws_s3_bucket_acl.b": {"bucket": ["aws_s3_bucket.b"]},
            "aws_security_group_rule.r": {"security_group_id": ["aws_security_group.sg"]},
            "aws_security_group_rule.e": {"security_group_id": ["aws_security_group.sg"]},
            "aws_vpc_security_group_ingress_rule.v": {"security_group_id": ["aws_security_group.sg"]},
        },
    )
    by = _types(resources_from_plan(plan))
    b = by["aws_s3_bucket.b"]
    assert b.region == "eu-west-1"
    assert b.config["name"] == "aws_s3_bucket.b"
    assert b.config["policy_is_public"] is True
    assert b.config["acl_grants"][0]["permission"] == "READ"
    ingress = by["aws_security_group.sg"].config["ingress"]
    assert {"protocol": "-1", "from_port": None, "to_port": None, "cidrs": ["0.0.0.0/0"], "ipv6_cidrs": []} in ingress
    assert {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidrs": [], "ipv6_cidrs": ["::/0"]} in ingress
    assert len(ingress) == 2


def test_iam_db_and_secret_mapping() -> None:
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    trust = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]})
    plan = _plan(
        [
            {"address": "aws_iam_policy.p", "values": {"name": "p", "policy": doc}},
            {"address": "aws_iam_role.r", "values": {"name": "r", "assume_role_policy": trust}},
            {"address": "aws_iam_role_policy_attachment.a", "values": {"role": "r", "policy_arn": None}},
            {"address": "aws_iam_role_policy.i", "values": {"role": "r", "name": "i", "policy": doc}},
            {"address": "aws_iam_user.u", "values": {"name": "u"}},
            {
                "address": "aws_iam_user_policy_attachment.ua",
                "values": {"user": "u", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            },
            {"address": "aws_iam_user_policy.ui", "values": {"user": "u", "name": "ui", "policy": doc}},
            {
                "address": "aws_db_instance.db",
                "values": {
                    "identifier": "db",
                    "engine": "mysql",
                    "publicly_accessible": True,
                    "storage_encrypted": False,
                    "vpc_security_group_ids": ["sg-1"],
                },
            },
            {"address": "aws_secretsmanager_secret.s", "values": {"name": "s"}},
            {"address": "aws_secretsmanager_secret_rotation.s", "values": {}},
            {"address": "aws_cloudtrail.t", "values": {"name": "t", "enable_logging": False}},
        ],
        {
            "aws_iam_role_policy_attachment.a": {"policy_arn": ["aws_iam_policy.p.arn", "aws_iam_policy.p"]},
            "aws_secretsmanager_secret_rotation.s": {"secret_id": ["aws_secretsmanager_secret.s"]},
        },
    )
    by = _types(resources_from_plan(plan))
    assert by["aws_iam_policy.p"].config["attached"] is True
    assert by["aws_iam_policy.p"].region == "global"
    role = by["aws_iam_role.r"].config
    assert role["trust_policy"]["Statement"][0]["Principal"] == {"AWS": "*"}
    assert role["attached_policy_arns"] == ["aws_iam_policy.p"]
    assert role["inline_policies"][0]["name"] == "i"
    user = by["aws_iam_user.u"].config
    assert user["attached_policy_arns"] == ["arn:aws:iam::aws:policy/AdministratorAccess"]
    assert user["has_console_password"] is False
    assert user["inline_policies"][0]["document"]["Statement"][0]["Action"] == "*"
    assert by["aws_db_instance.db"].config["publicly_accessible"] is True
    assert by["aws_secretsmanager_secret.s"].config["rotation_enabled"] is True
    assert by["terraform:cloudtrail-account"].config["has_logging_multi_region_trail"] is False


def test_plan_without_region_and_missing_source() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": "aws_kms_key.k", "type": "aws_kms_key", "values": {"is_enabled": False}},
                    {
                        "address": "data.aws_caller_identity.me",
                        "type": "aws_caller_identity",
                        "mode": "data",
                        "values": {},
                    },
                ]
            }
        }
    }
    [key] = resources_from_plan(plan)
    assert key.region == "unknown"
    assert key.config["state"] == "Disabled"
    with pytest.raises(ValueError):
        collect(Provider.TERRAFORM, mode=ScanMode.FIXTURE, source=None)
