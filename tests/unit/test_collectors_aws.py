import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from cspm.collectors import aws as aws_mod
from cspm.collectors.aws import AwsCollector, AwsSession, as_document, iso, policy_is_public
from cspm.contracts import Provider, Resource, ScanMode

REGION = "us-east-1"
KW: dict[str, Any] = {"region_name": REGION, "aws_access_key_id": "testing", "aws_secret_access_key": "testing"}
ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
}


def _seed() -> None:
    """Build one of everything with plain boto3; test setup is free to write."""
    s3 = boto3.client("s3", **KW)
    s3.create_bucket(Bucket="pub")
    s3.put_bucket_acl(Bucket="pub", ACL="public-read")
    s3.put_bucket_tagging(Bucket="pub", Tagging={"TagSet": [{"Key": "criticality", "Value": "high"}]})
    s3.create_bucket(Bucket="locked")
    s3.put_public_access_block(
        Bucket="locked",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="locked",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "k1"}}]
        },
    )
    s3.put_bucket_versioning(Bucket="locked", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_acl(Bucket="locked", ACL="log-delivery-write")
    s3.put_bucket_logging(
        Bucket="locked", BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": "locked", "TargetPrefix": "l/"}}
    )
    s3.put_bucket_policy(
        Bucket="locked",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": "arn:aws:s3:::locked",
                    }
                ],
            }
        ),
    )

    ec2 = boto3.client("ec2", **KW)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="open", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
        ],
    )
    ec2.create_tags(Resources=[sg], Tags=[{"Key": "data_sensitivity", "Value": "restricted"}])
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=1, Encrypted=False)

    iam = boto3.client("iam", **KW)
    arn = iam.create_policy(PolicyName="admin", PolicyDocument=json.dumps(ADMIN))["Policy"]["Arn"]
    iam.create_user(UserName="dev", Tags=[{"Key": "criticality", "Value": "high"}])
    iam.create_login_profile(UserName="dev", Password="Not-a-real-pass-1")
    iam.create_access_key(UserName="dev")
    iam.attach_user_policy(UserName="dev", PolicyArn=arn)
    iam.put_user_policy(UserName="dev", PolicyName="inline", PolicyDocument=json.dumps(ADMIN))
    iam.create_user(UserName="quiet")
    iam.create_role(RoleName="open-trust", AssumeRolePolicyDocument=json.dumps(TRUST))
    iam.put_role_policy(RoleName="open-trust", PolicyName="r", PolicyDocument=json.dumps(ADMIN))
    iam.attach_role_policy(RoleName="open-trust", PolicyArn=arn)
    iam.update_account_password_policy(MinimumPasswordLength=14, RequireSymbols=True, MaxPasswordAge=90)

    kms = boto3.client("kms", **KW)
    key = kms.create_key(Tags=[{"TagKey": "criticality", "TagValue": "high"}])["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key)
    off = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.disable_key(KeyId=off)

    trail_bucket = "trail-bucket"
    s3.create_bucket(Bucket=trail_bucket)
    ct = boto3.client("cloudtrail", **KW)
    ct.create_trail(Name="main", S3BucketName=trail_bucket, IsMultiRegionTrail=True, EnableLogFileValidation=True)
    ct.start_logging(Name="main")
    ct.create_trail(Name="side", S3BucketName=trail_bucket)

    sm = boto3.client("secretsmanager", **KW)
    sm.create_secret(Name="db-pass", SecretString="example-only", Tags=[{"Key": "criticality", "Value": "low"}])

    rds = boto3.client("rds", **KW)
    rds.create_db_instance(
        DBInstanceIdentifier="db1",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin1",
        MasterUserPassword="example-only-1",
        AllocatedStorage=20,
        PubliclyAccessible=True,
        VpcSecurityGroupIds=[sg],
    )

    acm = boto3.client("acm", **KW)
    acm.request_certificate(DomainName="example.test")


@pytest.fixture(scope="module")
def resources() -> Iterator[list[Resource]]:
    with mock_aws():
        _seed()
        session = AwsSession(mode=ScanMode.EMULATOR, endpoint=None, region=REGION)
        session.endpoint = None
        yield AwsCollector(session, [REGION]).collect()


def _one(resources: list[Resource], rtype: str, name: str | None = None, key: str = "name") -> Resource:
    matches = [r for r in resources if r.type == rtype and (name is None or r.config.get(key) == name)]
    assert len(matches) == 1, (rtype, name, [r.config for r in resources if r.type == rtype])
    return matches[0]


def test_every_resource_is_aws_and_typed(resources: list[Resource]) -> None:
    assert all(r.provider is Provider.AWS for r in resources)
    assert {r.type for r in resources} >= {
        "aws.s3.bucket",
        "aws.ec2.security_group",
        "aws.ec2.volume",
        "aws.ec2.region_settings",
        "aws.rds.instance",
        "aws.iam.policy",
        "aws.iam.user",
        "aws.iam.role",
        "aws.iam.account",
        "aws.cloudtrail.trail",
        "aws.cloudtrail.account",
        "aws.kms.key",
        "aws.secretsmanager.secret",
        "aws.acm.certificate",
    }


def test_public_bucket(resources: list[Resource]) -> None:
    b = _one(resources, "aws.s3.bucket", "pub")
    assert b.id == "arn:aws:s3:::pub"
    assert {"grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"} in b.config[
        "acl_grants"
    ]
    assert b.config["public_access_block"] == dict.fromkeys(
        ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"], False
    )
    assert b.config["encryption"] is None
    assert b.config["versioning"] == "Disabled"
    assert b.config["logging_enabled"] is False
    assert b.config["policy"] is None
    assert b.config["policy_is_public"] is False
    assert b.tags == {"criticality": "high"}


def test_locked_bucket(resources: list[Resource]) -> None:
    b = _one(resources, "aws.s3.bucket", "locked")
    assert all(b.config["public_access_block"].values())
    assert b.config["encryption"] == {"algorithm": "aws:kms", "kms_key_id": "k1"}
    assert b.config["versioning"] == "Enabled"
    assert b.config["logging_enabled"] is True
    assert b.config["policy"]["Statement"][0]["Principal"] == {"Service": "cloudtrail.amazonaws.com"}
    assert b.config["policy_is_public"] is False


def test_security_group(resources: list[Resource]) -> None:
    sg = _one(resources, "aws.ec2.security_group", "open")
    assert sg.id.startswith("arn:aws:ec2:us-east-1:123456789012:security-group/sg-")
    ingress = sg.config["ingress"]
    assert {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"], "ipv6_cidrs": []} in ingress
    assert {"protocol": "-1", "from_port": None, "to_port": None, "cidrs": [], "ipv6_cidrs": ["::/0"]} in ingress
    assert sg.tags["data_sensitivity"] == "restricted"


def test_volume_and_region_settings(resources: list[Resource]) -> None:
    vol = _one(resources, "aws.ec2.volume")
    assert vol.config["encrypted"] is False
    assert vol.config["attached_instance_ids"] == []
    rs = _one(resources, "aws.ec2.region_settings")
    assert rs.id == "123456789012:us-east-1:aws.ec2.region_settings"
    assert rs.config == {"ebs_encryption_by_default": False}


def test_rds(resources: list[Resource]) -> None:
    db = _one(resources, "aws.rds.instance", "db1", "identifier")
    assert db.config["engine"] == "postgres"
    assert db.config["publicly_accessible"] is True
    assert db.config["storage_encrypted"] is False
    assert len(db.config["security_group_ids"]) == 1


def test_iam(resources: list[Resource]) -> None:
    pol = _one(resources, "aws.iam.policy", "admin")
    assert pol.config["document"] == ADMIN
    assert pol.config["attached"] is True
    assert pol.config["aws_managed"] is False
    assert pol.region == "global"
    user = _one(resources, "aws.iam.user", "dev")
    assert user.config["has_console_password"] is True
    assert user.config["mfa_devices"] == 0
    [key] = user.config["access_keys"]
    assert key["status"] == "Active"
    assert len(key["key_id_suffix"]) == 4
    assert key["created"].endswith("Z")
    assert user.config["attached_policy_arns"] == [pol.id]
    assert user.config["inline_policies"] == [{"name": "inline", "document": ADMIN}]
    assert user.tags == {"criticality": "high"}
    quiet = _one(resources, "aws.iam.user", "quiet")
    assert quiet.config["has_console_password"] is False
    assert quiet.config["access_keys"] == []
    role = _one(resources, "aws.iam.role", "open-trust")
    assert role.config["trust_policy"] == TRUST
    assert role.config["attached_policy_arns"] == [pol.id]
    assert role.config["inline_policies"][0]["name"] == "r"


def test_iam_account(resources: list[Resource]) -> None:
    acct = _one(resources, "aws.iam.account")
    assert acct.id == "123456789012:global:aws.iam.account"
    assert acct.config["root_access_keys_present"] is False
    assert acct.config["password_policy"]["minimum_length"] == 14
    assert acct.config["password_policy"]["require_symbols"] is True
    assert acct.config["password_policy"]["max_age_days"] == 90


def test_cloudtrail(resources: list[Resource]) -> None:
    main = _one(resources, "aws.cloudtrail.trail", "main")
    assert main.config == {
        "name": "main",
        "is_multi_region": True,
        "is_logging": True,
        "log_file_validation": True,
        "home_region": REGION,
    }
    side = _one(resources, "aws.cloudtrail.trail", "side")
    assert side.config["is_logging"] is False
    acct = _one(resources, "aws.cloudtrail.account")
    assert acct.config == {"trail_names": ["main", "side"], "has_logging_multi_region_trail": True}


def test_kms(resources: list[Resource]) -> None:
    keys = [r for r in resources if r.type == "aws.kms.key"]
    on = next(k for k in keys if k.config["state"] == "Enabled")
    off = next(k for k in keys if k.config["state"] == "Disabled")
    assert on.config["rotation_enabled"] is True
    assert on.config["manager"] == "CUSTOMER"
    assert on.config["key_spec"] == "SYMMETRIC_DEFAULT"
    assert isinstance(on.config["policy"], dict)
    assert on.tags == {"criticality": "high"}
    assert off.config["rotation_enabled"] is False


def test_secret_and_cert(resources: list[Resource]) -> None:
    sec = _one(resources, "aws.secretsmanager.secret", "db-pass")
    assert sec.config["rotation_enabled"] is False
    assert sec.config["last_rotated"] is None
    assert sec.config["created"].endswith("Z")
    assert sec.tags == {"criticality": "low"}
    cert = _one(resources, "aws.acm.certificate", "example.test", "domain")
    assert cert.config["key_algorithm"] == "RSA_2048"
    assert set(cert.config) == {"domain", "not_after", "key_algorithm", "signature_algorithm", "status"}


def test_no_secret_values_in_output(resources: list[Resource]) -> None:
    assert "example-only" not in json.dumps([r.to_dict() for r in resources], default=str)


def test_collect_aws_uses_env_region(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    seen: dict[str, Any] = {}

    class Fake:
        def __init__(self, session: AwsSession, regions: list[str]) -> None:
            seen["regions"] = regions

        def collect(self) -> list[Resource]:
            return []

    monkeypatch.setattr(aws_mod, "AwsCollector", Fake)
    assert aws_mod.collect_aws(mode=ScanMode.EMULATOR, endpoint=None) == []
    assert seen["regions"] == ["eu-west-1"]


def test_helpers() -> None:
    assert iso(None) is None
    assert iso("2026-01-01T00:00:00Z") == "2026-01-01T00:00:00Z"
    assert iso(datetime(2026, 1, 1, 12)) == "2026-01-01T12:00:00Z"
    assert iso(datetime(2026, 1, 1, 12, tzinfo=UTC)) == "2026-01-01T12:00:00Z"
    assert as_document({"a": 1}) == {"a": 1}
    assert as_document('{"a": 1}') == {"a": 1}
    assert as_document("%7B%22a%22%3A%201%7D") == {"a": 1}
    assert as_document("[1]") == {}
    assert policy_is_public(None) is False
    assert policy_is_public({"Statement": {"Effect": "Allow", "Principal": "*"}}) is True
    assert policy_is_public({"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]}}]}) is True
    assert policy_is_public({"Statement": [{"Effect": "Allow", "Principal": "*", "Condition": {"x": 1}}]}) is False
    assert policy_is_public({"Statement": [{"Effect": "Deny", "Principal": "*"}]}) is False


def test_optional_reraises_unexpected_errors() -> None:
    def boom() -> None:
        raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetBucketPolicy")

    with pytest.raises(ClientError):
        aws_mod._optional(boom, "NoSuchBucketPolicy")
