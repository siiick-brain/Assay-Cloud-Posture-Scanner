"""AWS collector. Every client carries the read-only allowlist hook."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from cspm.collectors.guard import check_emulator_endpoint, check_live_allowed, enforce_allowlist
from cspm.contracts import Provider, Resource, ScanMode

DEFAULT_ENDPOINT = "http://localhost:5000"
DEFAULT_REGION = "us-east-1"
EMULATOR_KEY = "testing"
PUBLIC_PRINCIPALS = ("*", "arn:aws:iam::*:root")
ALL_KEY_TYPES = [
    "RSA_1024",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "EC_prime256v1",
    "EC_secp384r1",
    "EC_secp521r1",
]

Client = Any


class AwsSession:
    """Builds guarded clients for one scan."""

    def __init__(self, *, mode: ScanMode, endpoint: str | None, region: str) -> None:
        self.mode = mode
        self.region = region
        if mode is ScanMode.LIVE:
            check_live_allowed()
            if endpoint is not None:
                raise ValueError("live mode talks to AWS directly, drop the endpoint")
            self.endpoint: str | None = None
            creds = _env_credentials()
            self._session = boto3.Session(
                aws_access_key_id=creds["aws_access_key_id"],
                aws_secret_access_key=creds["aws_secret_access_key"],
                aws_session_token=creds.get("aws_session_token"),
                region_name=region,
            )
        else:
            self.endpoint = check_emulator_endpoint(endpoint or DEFAULT_ENDPOINT)
            # Real keys never travel to an emulator, so emulator mode always uses the Moto dummies.
            self._session = boto3.Session(
                aws_access_key_id=EMULATOR_KEY, aws_secret_access_key=EMULATOR_KEY, region_name=region
            )

    def client(self, service: str, region: str | None = None) -> Client:
        client = self._session.client(
            service,  # type: ignore[call-overload]
            region_name=region or self.region,
            endpoint_url=self.endpoint,
            config=Config(connect_timeout=5, read_timeout=30, retries={"max_attempts": 2, "mode": "standard"}),
        )
        client.meta.events.register("before-call", enforce_allowlist)
        return client


def _env_credentials() -> dict[str, str]:
    key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not key or not secret:
        raise RuntimeError("live mode reads credentials only from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
    creds = {"aws_access_key_id": key, "aws_secret_access_key": secret}
    token = os.environ.get("AWS_SESSION_TOKEN")
    if token:
        creds["aws_session_token"] = token
    return creds


def iso(value: datetime | str | None) -> str | None:
    """Format a timestamp as an ISO 8601 UTC string."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def as_document(raw: Any) -> dict[str, Any]:
    """IAM returns policy documents either decoded or URL-encoded JSON depending on the path."""
    if isinstance(raw, dict):
        return raw
    text = unquote(raw) if isinstance(raw, str) and raw.startswith("%7B") else raw
    parsed = json.loads(text)
    return parsed if isinstance(parsed, dict) else {}


def _error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def _optional(call: Callable[[], Any], *codes: str) -> Any:
    """Return None when the API reports the setting as absent."""
    try:
        return call()
    except ClientError as exc:
        if _error_code(exc) in codes:
            return None
        raise


def _rotation(client: Client, key_id: str) -> bool:
    try:
        return bool(client.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"])
    except ClientError as exc:
        if _error_code(exc) == "UnsupportedOperationException":
            return False
        raise


def _paginate(client: Client, op: str, key: str, **kwargs: Any) -> list[Any]:
    items: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def _tags(items: Iterable[dict[str, Any]] | None, key: str = "Key", value: str = "Value") -> dict[str, str]:
    return {str(t[key]): str(t[value]) for t in items or []}


def policy_is_public(policy: dict[str, Any] | None) -> bool:
    """Fallback when GetBucketPolicyStatus is unavailable: any unconditioned Allow to everyone."""
    if not policy:
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        principal = st.get("Principal")
        values: list[Any] = []
        if isinstance(principal, str):
            values = [principal]
        elif isinstance(principal, dict):
            aws = principal.get("AWS", [])
            values = aws if isinstance(aws, list) else [aws]
        if any(v in PUBLIC_PRINCIPALS for v in values):
            return True
    return False


class AwsCollector:
    """Collects every resource type in docs/contracts.md for the given regions."""

    def __init__(self, session: AwsSession, regions: Sequence[str]) -> None:
        self.s = session
        self.regions = list(regions)
        self.account = str(session.client("sts").get_caller_identity()["Account"])

    def collect(self) -> list[Resource]:
        out: list[Resource] = []
        out += self.s3()
        out += self.iam()
        trails: dict[str, Resource] = {}
        for region in self.regions:
            out += self.ec2(region)
            out += self.rds(region)
            out += self.kms(region)
            out += self.secrets(region)
            out += self.acm(region)
            for trail in self.trails(region):
                trails.setdefault(trail.id, trail)
        out += list(trails.values())
        out.append(self.trail_account(list(trails.values())))
        return out

    def _account_id(self, region: str, rtype: str) -> str:
        return f"{self.account}:{region}:{rtype}"

    def s3(self) -> list[Resource]:
        client = self.s.client("s3")
        out = []
        for bucket in client.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            loc = client.get_bucket_location(Bucket=name).get("LocationConstraint") or DEFAULT_REGION
            if self.s.mode is ScanMode.LIVE and loc not in self.regions:
                continue
            out.append(self._bucket(client, name, loc))
        return out

    def _bucket(self, client: Client, name: str, region: str) -> Resource:
        acl = client.get_bucket_acl(Bucket=name)
        grants = [
            {"grantee_uri": g["Grantee"]["URI"], "permission": g["Permission"]}
            for g in acl.get("Grants", [])
            if g.get("Grantee", {}).get("URI")
        ]
        raw_policy = _optional(lambda: client.get_bucket_policy(Bucket=name)["Policy"], "NoSuchBucketPolicy")
        policy = json.loads(raw_policy) if raw_policy else None
        status = None
        if policy is not None:
            status = _optional(
                lambda: client.get_bucket_policy_status(Bucket=name)["PolicyStatus"],
                "NoSuchBucketPolicy",
                "NotImplemented",
            )
        is_public = bool(status["IsPublic"]) if status else policy_is_public(policy)
        pab = (
            _optional(
                lambda: client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"],
                "NoSuchPublicAccessBlockConfiguration",
            )
            or {}
        )
        enc_rules = _optional(
            lambda: client.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"],
            "ServerSideEncryptionConfigurationNotFoundError",
        )
        encryption = None
        if enc_rules:
            default = enc_rules[0].get("ApplyServerSideEncryptionByDefault", {})
            encryption = {"algorithm": default.get("SSEAlgorithm"), "kms_key_id": default.get("KMSMasterKeyID")}
        versioning = client.get_bucket_versioning(Bucket=name).get("Status") or "Disabled"
        logging = "LoggingEnabled" in client.get_bucket_logging(Bucket=name)
        tags = _optional(lambda: client.get_bucket_tagging(Bucket=name)["TagSet"], "NoSuchTagSet")
        config = {
            "name": name,
            "acl_grants": grants,
            "policy": policy,
            "policy_is_public": is_public,
            "public_access_block": {
                "block_public_acls": bool(pab.get("BlockPublicAcls", False)),
                "ignore_public_acls": bool(pab.get("IgnorePublicAcls", False)),
                "block_public_policy": bool(pab.get("BlockPublicPolicy", False)),
                "restrict_public_buckets": bool(pab.get("RestrictPublicBuckets", False)),
            },
            "encryption": encryption,
            "versioning": versioning,
            "logging_enabled": logging,
        }
        return Resource(f"arn:aws:s3:::{name}", "aws.s3.bucket", Provider.AWS, region, config, _tags(tags))

    def ec2(self, region: str) -> list[Resource]:
        client = self.s.client("ec2", region)
        out = []
        for sg in _paginate(client, "describe_security_groups", "SecurityGroups"):
            ingress = []
            for perm in sg.get("IpPermissions", []):
                proto = str(perm.get("IpProtocol", "-1"))
                all_ports = proto == "-1"
                ingress.append(
                    {
                        "protocol": proto,
                        "from_port": None if all_ports else perm.get("FromPort"),
                        "to_port": None if all_ports else perm.get("ToPort"),
                        "cidrs": [r["CidrIp"] for r in perm.get("IpRanges", [])],
                        "ipv6_cidrs": [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])],
                    }
                )
            gid = sg["GroupId"]
            config = {"group_id": gid, "name": sg.get("GroupName", ""), "vpc_id": sg.get("VpcId"), "ingress": ingress}
            arn = f"arn:aws:ec2:{region}:{self.account}:security-group/{gid}"
            out.append(Resource(arn, "aws.ec2.security_group", Provider.AWS, region, config, _tags(sg.get("Tags"))))
        for vol in _paginate(client, "describe_volumes", "Volumes"):
            vid = vol["VolumeId"]
            config = {
                "volume_id": vid,
                "encrypted": bool(vol.get("Encrypted", False)),
                "kms_key_id": vol.get("KmsKeyId"),
                "attached_instance_ids": [a["InstanceId"] for a in vol.get("Attachments", []) if a.get("InstanceId")],
            }
            arn = f"arn:aws:ec2:{region}:{self.account}:volume/{vid}"
            out.append(Resource(arn, "aws.ec2.volume", Provider.AWS, region, config, _tags(vol.get("Tags"))))
        ebs_default = bool(client.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False))
        out.append(
            Resource(
                self._account_id(region, "aws.ec2.region_settings"),
                "aws.ec2.region_settings",
                Provider.AWS,
                region,
                {"ebs_encryption_by_default": ebs_default},
            )
        )
        return out

    def rds(self, region: str) -> list[Resource]:
        client = self.s.client("rds", region)
        out = []
        for db in _paginate(client, "describe_db_instances", "DBInstances"):
            config = {
                "identifier": db["DBInstanceIdentifier"],
                "engine": db.get("Engine", ""),
                "publicly_accessible": bool(db.get("PubliclyAccessible", False)),
                "storage_encrypted": bool(db.get("StorageEncrypted", False)),
                "security_group_ids": [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])],
            }
            tags = _tags(db.get("TagList"))
            out.append(Resource(db["DBInstanceArn"], "aws.rds.instance", Provider.AWS, region, config, tags))
        return out

    def iam(self) -> list[Resource]:
        client = self.s.client("iam")
        out = []
        policies = _paginate(client, "list_policies", "Policies", Scope="Local")
        policies += _paginate(client, "list_policies", "Policies", Scope="AWS", OnlyAttached=True)
        for pol in policies:
            version = client.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
            config = {
                "name": pol["PolicyName"],
                "arn": pol["Arn"],
                "document": as_document(version["PolicyVersion"]["Document"]),
                "attached": int(pol.get("AttachmentCount", 0)) > 0,
                "aws_managed": pol["Arn"].startswith("arn:aws:iam::aws:policy/"),
            }
            out.append(Resource(pol["Arn"], "aws.iam.policy", Provider.AWS, "global", config, _tags(pol.get("Tags"))))
        for user in _paginate(client, "list_users", "Users"):
            out.append(self._user(client, user))
        for role in _paginate(client, "list_roles", "Roles"):
            out.append(self._role(client, role))
        out.append(self._iam_account(client))
        return out

    def _user(self, client: Client, user: dict[str, Any]) -> Resource:
        name = user["UserName"]
        profile = _optional(lambda: client.get_login_profile(UserName=name), "NoSuchEntity")
        keys = [
            {
                "key_id_suffix": k["AccessKeyId"][-4:],
                "status": k.get("Status", ""),
                "created": iso(k.get("CreateDate")),
            }
            for k in _paginate(client, "list_access_keys", "AccessKeyMetadata", UserName=name)
        ]
        inline = [
            {"name": p, "document": as_document(client.get_user_policy(UserName=name, PolicyName=p)["PolicyDocument"])}
            for p in _paginate(client, "list_user_policies", "PolicyNames", UserName=name)
        ]
        config = {
            "name": name,
            "has_console_password": profile is not None,
            "mfa_devices": len(_paginate(client, "list_mfa_devices", "MFADevices", UserName=name)),
            "access_keys": keys,
            "attached_policy_arns": [
                p["PolicyArn"]
                for p in _paginate(client, "list_attached_user_policies", "AttachedPolicies", UserName=name)
            ],
            "inline_policies": inline,
        }
        tags = _tags(_paginate(client, "list_user_tags", "Tags", UserName=name))
        return Resource(user["Arn"], "aws.iam.user", Provider.AWS, "global", config, tags)

    def _role(self, client: Client, role: dict[str, Any]) -> Resource:
        name = role["RoleName"]
        trust = role.get("AssumeRolePolicyDocument") or client.get_role(RoleName=name)["Role"].get(
            "AssumeRolePolicyDocument", {}
        )
        inline = [
            {"name": p, "document": as_document(client.get_role_policy(RoleName=name, PolicyName=p)["PolicyDocument"])}
            for p in _paginate(client, "list_role_policies", "PolicyNames", RoleName=name)
        ]
        config = {
            "name": name,
            "trust_policy": as_document(trust),
            "attached_policy_arns": [
                p["PolicyArn"]
                for p in _paginate(client, "list_attached_role_policies", "AttachedPolicies", RoleName=name)
            ],
            "inline_policies": inline,
        }
        tags = _tags(_paginate(client, "list_role_tags", "Tags", RoleName=name))
        return Resource(role["Arn"], "aws.iam.role", Provider.AWS, "global", config, tags)

    def _iam_account(self, client: Client) -> Resource:
        summary = client.get_account_summary().get("SummaryMap", {})
        raw = _optional(lambda: client.get_account_password_policy()["PasswordPolicy"], "NoSuchEntity")
        policy = None
        if raw is not None:
            policy = {
                "minimum_length": raw.get("MinimumPasswordLength", 0),
                "require_symbols": bool(raw.get("RequireSymbols", False)),
                "require_numbers": bool(raw.get("RequireNumbers", False)),
                "require_uppercase": bool(raw.get("RequireUppercaseCharacters", False)),
                "require_lowercase": bool(raw.get("RequireLowercaseCharacters", False)),
                "max_age_days": raw.get("MaxPasswordAge"),
            }
        config = {
            "root_access_keys_present": int(summary.get("AccountAccessKeysPresent", 0)) > 0,
            "root_mfa_enabled": int(summary.get("AccountMFAEnabled", 0)) > 0,
            "password_policy": policy,
        }
        rid = self._account_id("global", "aws.iam.account")
        return Resource(rid, "aws.iam.account", Provider.AWS, "global", config)

    def trails(self, region: str) -> list[Resource]:
        client = self.s.client("cloudtrail", region)
        out = []
        for trail in client.describe_trails(includeShadowTrails=False).get("trailList", []):
            arn = trail["TrailARN"]
            status = client.get_trail_status(Name=arn)
            home = trail.get("HomeRegion", region)
            config = {
                "name": trail["Name"],
                "is_multi_region": bool(trail.get("IsMultiRegionTrail", False)),
                "is_logging": bool(status.get("IsLogging", False)),
                "log_file_validation": bool(trail.get("LogFileValidationEnabled", False)),
                "home_region": home,
            }
            out.append(Resource(arn, "aws.cloudtrail.trail", Provider.AWS, home, config))
        return out

    def trail_account(self, trails: Sequence[Resource]) -> Resource:
        config = {
            "trail_names": sorted(str(t.config["name"]) for t in trails),
            "has_logging_multi_region_trail": any(
                t.config["is_multi_region"] and t.config["is_logging"] for t in trails
            ),
        }
        rid = self._account_id("global", "aws.cloudtrail.account")
        return Resource(rid, "aws.cloudtrail.account", Provider.AWS, "global", config)

    def kms(self, region: str) -> list[Resource]:
        client = self.s.client("kms", region)
        out = []
        for key in _paginate(client, "list_keys", "Keys"):
            meta = client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            kid = meta["KeyId"]
            manager = meta.get("KeyManager", "CUSTOMER")
            rotation = False
            if manager == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                rotation = bool(_rotation(client, kid))
            raw_policy = client.get_key_policy(KeyId=kid, PolicyName="default").get("Policy")
            tags: list[Any] = []
            if manager == "CUSTOMER":
                tags = client.list_resource_tags(KeyId=kid).get("Tags", [])
            config = {
                "key_id": kid,
                "manager": manager,
                "state": meta.get("KeyState", ""),
                "rotation_enabled": rotation,
                "policy": json.loads(raw_policy) if raw_policy else None,
                "key_spec": meta.get("KeySpec") or meta.get("CustomerMasterKeySpec", ""),
            }
            out.append(
                Resource(meta["Arn"], "aws.kms.key", Provider.AWS, region, config, _tags(tags, "TagKey", "TagValue"))
            )
        return out

    def secrets(self, region: str) -> list[Resource]:
        client = self.s.client("secretsmanager", region)
        out = []
        for sec in _paginate(client, "list_secrets", "SecretList"):
            config = {
                "name": sec["Name"],
                "rotation_enabled": bool(sec.get("RotationEnabled", False)),
                "last_rotated": iso(sec.get("LastRotatedDate")),
                "created": iso(sec.get("CreatedDate")) or "",
            }
            out.append(
                Resource(sec["ARN"], "aws.secretsmanager.secret", Provider.AWS, region, config, _tags(sec.get("Tags")))
            )
        return out

    def acm(self, region: str) -> list[Resource]:
        client = self.s.client("acm", region)
        out = []
        summaries = _paginate(
            client, "list_certificates", "CertificateSummaryList", Includes={"keyTypes": ALL_KEY_TYPES}
        )
        for summary in summaries:
            arn = summary["CertificateArn"]
            cert = client.describe_certificate(CertificateArn=arn)["Certificate"]
            config = {
                "domain": cert.get("DomainName", ""),
                "not_after": iso(cert.get("NotAfter")) or "",
                "key_algorithm": str(cert.get("KeyAlgorithm", "")).replace("-", "_"),
                "signature_algorithm": cert.get("SignatureAlgorithm", ""),
                "status": cert.get("Status", ""),
            }
            tags = client.list_tags_for_certificate(CertificateArn=arn).get("Tags", [])
            out.append(Resource(arn, "aws.acm.certificate", Provider.AWS, region, config, _tags(tags)))
        return out


def collect_aws(*, mode: ScanMode, endpoint: str | None, regions: Sequence[str] | None = None) -> list[Resource]:
    """Collect AWS resources from the emulator, or from AWS itself when live mode is unlocked."""
    chosen = list(regions or [os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_REGION])
    session = AwsSession(mode=mode, endpoint=endpoint, region=chosen[0])
    return AwsCollector(session, chosen).collect()
