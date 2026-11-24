"""Edge cases for IAM policy parsing, security group matching and time based rules."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from cspm.contracts import Provider, Resource, ScanContext, ScanMode
from rules import ALL_RULES, _base
from tests.unit.test_rules_cases import ADMIN, CTX, doc, make, run, sg_rule


@pytest.mark.parametrize(
    ("action", "hit"),
    [("*", True), (["*"], True), (["s3:GetObject", "*"], True), ("*:*", True), ("s3:*", False), ([], False)],
)
def test_admin_action_string_or_list(action: Any, hit: bool) -> None:
    res = make("aws.iam.policy", document=doc({"Effect": "Allow", "Action": action, "Resource": "*"}))
    assert bool(run("ASSAY-IAM-001", res)) is hit


def test_admin_needs_resource_star() -> None:
    res = make("aws.iam.policy", document=doc({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"}))
    assert run("ASSAY-IAM-001", res) == []


def test_not_action_allow_counts_as_admin() -> None:
    res = make("aws.iam.policy", document=doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
    assert run("ASSAY-IAM-001", res)


def test_deny_star_is_not_admin() -> None:
    res = make("aws.iam.policy", document=doc({"Effect": "Deny", "Action": "*", "Resource": "*"}))
    assert run("ASSAY-IAM-001", res) == []


def test_admin_with_condition_is_flagged_and_noted() -> None:
    stmt = {**ADMIN, "Sid": "Mfa", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    (v,) = run("ASSAY-IAM-001", make("aws.iam.policy", document=doc(stmt)))
    assert v.evidence["conditional_statements"] == ["Mfa"]


def test_admin_exposure_follows_attachment() -> None:
    assert run("ASSAY-IAM-001", make("aws.iam.policy", document=doc(ADMIN)))[0].exposure == "internal"
    assert run("ASSAY-IAM-001", make("aws.iam.policy", document=doc(ADMIN), attached=False))[0].exposure == "none"


def test_aws_managed_policies_skipped() -> None:
    res = make("aws.iam.policy", document=doc(ADMIN), aws_managed=True)
    assert run("ASSAY-IAM-001", res) == []
    assert (
        run("ASSAY-IAM-002", make("aws.iam.policy", document=doc({**ADMIN, "Action": "s3:*"}), aws_managed=True)) == []
    )


def test_single_statement_dict_is_parsed() -> None:
    res = make("aws.iam.policy", document={"Statement": ADMIN})
    assert run("ASSAY-IAM-001", res)
    assert _base.statements(None) == []
    assert _base.statements({"Statement": ["junk", ADMIN]}) == [ADMIN]


def test_service_wildcard_string_action() -> None:
    res = make("aws.iam.policy", document=doc({"Effect": "Allow", "Action": "EC2:*", "Resource": "*"}))
    assert run("ASSAY-IAM-002", res)[0].evidence["actions"] == ["EC2:*"]
    partial = make("aws.iam.policy", document=doc({"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}))
    assert run("ASSAY-IAM-002", partial) == []


@pytest.mark.parametrize(
    ("principal", "hit"),
    [
        ("*", True),
        ({"AWS": "*"}, True),
        ({"AWS": ["arn:aws:iam::111122223333:root", "*"]}, True),
        ({"Federated": "*"}, True),
        ({"AWS": "arn:aws:iam::111122223333:root"}, False),
        ({"Service": "lambda.amazonaws.com"}, False),
    ],
)
def test_trust_principal_forms(principal: Any, hit: bool) -> None:
    res = make(
        "aws.iam.role", trust_policy=doc({"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"})
    )
    assert bool(run("ASSAY-IAM-006", res)) is hit


def test_wildcard_principal_with_condition_passes() -> None:
    stmt = {
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}},
    }
    assert run("ASSAY-IAM-006", make("aws.iam.role", trust_policy=doc(stmt))) == []
    kms = make("aws.kms.key", policy=doc({**stmt, "Action": "kms:Decrypt"}))
    assert run("ASSAY-KMS-002", kms) == []


def test_user_admin_via_inline_and_customer_policy() -> None:
    inline = make("aws.iam.user", inline_policies=[{"name": "god", "document": doc(ADMIN)}])
    assert run("ASSAY-IAM-003", inline)[0].evidence["admin_inline_policies"] == ["god"]
    policy = make("aws.iam.policy", document=doc(ADMIN))
    user = make("aws.iam.user", attached_policy_arns=[policy.config["arn"]])
    ctx = ScanContext(now=CTX.now, mode=CTX.mode, inventory=(policy, user))
    assert run("ASSAY-IAM-003", user, ctx)
    assert run("ASSAY-IAM-003", user) == []


def test_user_without_console_password_needs_no_mfa() -> None:
    assert run("ASSAY-IAM-004", make("aws.iam.user", has_console_password=False, mfa_devices=0)) == []


def test_inactive_or_undated_old_key_ignored() -> None:
    keys = [
        {"key_id_suffix": "A", "status": "Inactive", "created": "2020-01-01T00:00:00Z"},
        {"key_id_suffix": "B", "status": "Active", "created": None},
        {"key_id_suffix": "C", "status": "Active", "created": "not a date"},
    ]
    assert run("ASSAY-IAM-005", make("aws.iam.user", access_keys=keys)) == []


def test_key_age_uses_ctx_now_not_clock() -> None:
    key = [{"key_id_suffix": "A", "status": "Active", "created": "2026-01-01T00:00:00"}]
    early = ScanContext(now=datetime(2026, 2, 1), mode=ScanMode.FIXTURE)
    assert run("ASSAY-IAM-005", make("aws.iam.user", access_keys=key), early) == []
    assert run("ASSAY-IAM-005", make("aws.iam.user", access_keys=key))


def test_short_password_policy() -> None:
    weak = make("aws.iam.account", password_policy={"minimum_length": 8})
    assert run("ASSAY-IAM-008", weak)[0].evidence["minimum_length"] == 8


@pytest.mark.parametrize(
    ("entry", "rule_id", "hit"),
    [
        (sg_rule(protocol="-1", low=None, high=None), "ASSAY-EC2-001", True),
        (sg_rule(protocol="-1", low=None, high=None), "ASSAY-EC2-002", True),
        (sg_rule(protocol="-1", low=None, high=None), "ASSAY-EC2-003", True),
        (sg_rule(low=0, high=1024), "ASSAY-EC2-001", True),
        (sg_rule(low=20, high=25), "ASSAY-EC2-001", True),
        (sg_rule(low=23, high=80), "ASSAY-EC2-001", False),
        (sg_rule(protocol="udp", low=22, high=22), "ASSAY-EC2-001", False),
        (sg_rule(protocol="6", low=22, high=22), "ASSAY-EC2-001", True),
        (sg_rule(protocol="tcp", low=None, high=None), "ASSAY-EC2-001", True),
        (sg_rule(cidrs=(), v6=("::/0",)), "ASSAY-EC2-001", True),
        (sg_rule(cidrs=("10.0.0.0/8",), v6=("2001:db8::/32",)), "ASSAY-EC2-001", False),
        (sg_rule(protocol="udp", low=3389, high=3389), "ASSAY-EC2-002", True),
        (sg_rule(low=3000, high=4000), "ASSAY-EC2-003", True),
        (sg_rule(low=0, high=65535), "ASSAY-EC2-004", True),
        (sg_rule(low=22, high=22), "ASSAY-EC2-004", False),
        (sg_rule(protocol="-1", low=None, high=None, cidrs=("10.0.0.0/8",)), "ASSAY-EC2-004", False),
    ],
)
def test_security_group_matching(entry: dict[str, Any], rule_id: str, hit: bool) -> None:
    res = make("aws.ec2.security_group", ingress=[entry])
    result = run(rule_id, res)
    assert bool(result) is hit
    if hit:
        assert result[0].exposure == "internet"


def test_bad_cidr_is_not_internet() -> None:
    assert not _base.is_internet_cidr("not-a-cidr")
    assert _base.is_internet_cidr("::0/0")


def test_s3_policy_public_and_bpa_restrict() -> None:
    open_policy = doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    no_bpa = {"public_access_block": {}}
    assert run("ASSAY-S3-001", make("aws.s3.bucket", policy=open_policy, **no_bpa))[0].exposure == "internet"
    assert run("ASSAY-S3-001", make("aws.s3.bucket", policy_is_public=True, **no_bpa))[0].evidence["policy_is_public"]
    assert run("ASSAY-S3-001", make("aws.s3.bucket", policy=open_policy)) == []


def test_kms_rotation_skips_non_applicable_keys() -> None:
    for overrides in ({"manager": "AWS"}, {"state": "PendingDeletion"}, {"key_spec": "RSA_2048"}):
        assert run("ASSAY-KMS-001", make("aws.kms.key", rotation_enabled=False, **overrides)) == []


def test_secret_without_rotation_uses_created() -> None:
    old = make("aws.secretsmanager.secret", last_rotated=None, created="2026-01-01T00:00:00Z", rotation_enabled=False)
    assert run("ASSAY-SEC-001", old)[0].evidence["rotation_enabled"] is False
    young = make("aws.secretsmanager.secret", last_rotated=None, created="2026-11-20T00:00:00Z")
    assert run("ASSAY-SEC-001", young) == []


def test_certificate_edges() -> None:
    expired = make("aws.acm.certificate", not_after="2026-01-01T00:00:00Z", status="EXPIRED")
    assert run("ASSAY-ACM-001", expired)[0].evidence["days_left"] < 0
    assert run("ASSAY-ACM-001", make("aws.acm.certificate", not_after="")) == []
    assert run("ASSAY-ACM-002", make("aws.acm.certificate", signature_algorithm="SHA1WITHRSA"))
    curve = "EC_prime256v1"
    assert run("ASSAY-ACM-002", make("aws.acm.certificate", key_algorithm=curve)) == []


def test_azure_container_blocked_by_account() -> None:
    account = make("azure.storage.account", allow_blob_public_access=False)
    container = make("azure.storage.container", public_access="Blob")
    blocked = ScanContext(now=CTX.now, mode=CTX.mode, inventory=(account,))
    assert run("ASSAY-AZ-STG-001", container, blocked) == []
    open_account = make("azure.storage.account", allow_blob_public_access=True)
    allowed = ScanContext(now=CTX.now, mode=CTX.mode, inventory=(open_account,))
    assert run("ASSAY-AZ-STG-001", container, allowed)


def test_nsg_any_any_variants() -> None:
    base = {"name": "r", "direction": "Inbound", "access": "Allow", "protocol": "*", "priority": 100}
    hit = make(
        "azure.network.nsg",
        security_rules=[{**base, "source_address_prefix": "Internet", "destination_port_range": "0-65535"}],
    )
    assert run("ASSAY-AZ-NSG-001", hit)
    deny = make(
        "azure.network.nsg",
        security_rules=[{**base, "access": "Deny", "source_address_prefix": "*", "destination_port_range": "*"}],
    )
    assert run("ASSAY-AZ-NSG-001", deny) == []
    outbound = make(
        "azure.network.nsg",
        security_rules=[{**base, "direction": "Outbound", "source_address_prefix": "*", "destination_port_range": "*"}],
    )
    assert run("ASSAY-AZ-NSG-001", outbound) == []


def test_parse_time_variants() -> None:
    assert _base.parse_time(None) is None
    aware = _base.parse_time(datetime(2026, 1, 1))
    assert aware is not None and aware.tzinfo is not None
    assert _base.age_days("2026-11-22T12:00:00+00:00", datetime(2026, 11, 23, 12)) == pytest.approx(1.0)


def test_resource_without_config_keys_does_not_crash() -> None:
    for rule in ALL_RULES:
        bare = Resource(id="x", type=rule.meta.resource_types[0], provider=Provider.AWS, region="r")
        rule.evaluate(bare, CTX)
