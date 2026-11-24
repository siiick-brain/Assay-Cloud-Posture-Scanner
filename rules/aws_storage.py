"""S3, EBS and RDS rules."""

from __future__ import annotations

from typing import Any

from cspm.contracts.resource import Resource
from cspm.contracts.rule import ScanContext, Violation
from rules._base import meta, wildcard_principal_statements

_PUBLIC_GRANTEES = ("AllUsers", "AuthenticatedUsers")
_BPA_FLAGS = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")


class S3PublicRead:
    meta = meta(
        "ASSAY-S3-001",
        rationale="An ACL grant to AllUsers or AuthenticatedUsers, or a bucket policy open to any principal, "
        "lets anyone on the internet read or change objects.",
        impact="Object data can be listed and downloaded by anyone, which is the most common cloud data leak.",
        remediation="Remove public ACL grants and wildcard policy statements, then turn on Block Public Access.",
        references=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        bpa: dict[str, Any] = dict(cfg.get("public_access_block") or {})
        evidence: dict[str, Any] = {}
        # Block Public Access settings override grants, so only effective exposure is reported.
        if not bpa.get("ignore_public_acls"):
            grants = [
                f"{g.get('grantee_uri')}:{g.get('permission')}"
                for g in cfg.get("acl_grants") or []
                if any(p in str(g.get("grantee_uri") or "") for p in _PUBLIC_GRANTEES)
            ]
            if grants:
                evidence["public_acl_grants"] = grants
        if not bpa.get("restrict_public_buckets"):
            open_statements = wildcard_principal_statements(cfg.get("policy"))
            if open_statements:
                evidence["public_policy_statements"] = open_statements
            elif cfg.get("policy_is_public"):
                evidence["policy_is_public"] = True
        if not evidence:
            return []
        evidence["bucket"] = cfg.get("name")
        return [Violation(evidence=evidence, exposure="internet")]


class S3BlockPublicAccess:
    meta = meta(
        "ASSAY-S3-002",
        rationale="Block Public Access is the guard rail that stops a later ACL or policy edit from exposing data.",
        impact="A single mistaken grant or policy change would make the bucket public.",
        remediation="Turn on all four Block Public Access settings on the bucket and at account level.",
        references=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        bpa = resource.config.get("public_access_block") or {}
        off = [flag for flag in _BPA_FLAGS if not bpa.get(flag)]
        if not off:
            return []
        return [Violation(evidence={"bucket": resource.config.get("name"), "settings_off": off})]


class S3DefaultEncryption:
    meta = meta(
        "ASSAY-S3-003",
        rationale="Without a default encryption configuration the bucket relies on each writer to request it.",
        impact="Objects may be stored without the key controls and audit trail a KMS key gives.",
        remediation="Set default encryption to SSE-KMS with a customer managed key, or at least SSE-S3.",
        references=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        enc = resource.config.get("encryption")
        if enc and enc.get("algorithm"):
            return []
        return [Violation(evidence={"bucket": resource.config.get("name"), "encryption": None})]


class S3Versioning:
    meta = meta(
        "ASSAY-S3-004",
        rationale="Versioning keeps earlier object versions so a delete or overwrite can be undone.",
        impact="Ransomware, a bad deploy or an accidental delete destroys data with no way back.",
        remediation="Enable versioning and add a lifecycle rule to expire old versions.",
        references=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        state = resource.config.get("versioning") or "Disabled"
        if state == "Enabled":
            return []
        return [Violation(evidence={"bucket": resource.config.get("name"), "versioning": state})]


class S3AccessLogging:
    meta = meta(
        "ASSAY-S3-005",
        rationale="Server access logs are the record of who read or wrote objects.",
        impact="After a leak there is no evidence of what was accessed or by whom.",
        remediation="Enable server access logging to a separate log bucket, or CloudTrail data events.",
        references=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        if resource.config.get("logging_enabled"):
            return []
        return [Violation(evidence={"bucket": resource.config.get("name"), "logging_enabled": False})]


class EbsVolumeEncryption:
    meta = meta(
        "ASSAY-EC2-005",
        rationale="An unencrypted volume and its snapshots hold data in the clear.",
        impact="A shared or copied snapshot exposes the whole disk content.",
        remediation="Create an encrypted copy from a snapshot, swap the volume and turn on EBS default encryption.",
        references=("https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if cfg.get("encrypted"):
            return []
        return [
            Violation(
                evidence={
                    "volume_id": cfg.get("volume_id"),
                    "encrypted": False,
                    "attached_instance_ids": list(cfg.get("attached_instance_ids") or []),
                }
            )
        ]


class EbsEncryptionByDefault:
    meta = meta(
        "ASSAY-EC2-006",
        rationale="Default encryption makes every new volume encrypted without relying on each launch template.",
        impact="New volumes in this region can be created unencrypted.",
        remediation="Turn on EBS encryption by default in every region you use.",
        references=("https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        if resource.config.get("ebs_encryption_by_default"):
            return []
        return [Violation(evidence={"region": resource.region, "ebs_encryption_by_default": False})]


class RdsPublic:
    meta = meta(
        "ASSAY-RDS-001",
        rationale="A publicly accessible instance gets a public DNS name and address.",
        impact="The database login is reachable from the internet and open to password guessing and exploits.",
        remediation="Set PubliclyAccessible to false and reach the database through private subnets.",
        references=(
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
        ),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if not cfg.get("publicly_accessible"):
            return []
        return [
            Violation(
                evidence={
                    "identifier": cfg.get("identifier"),
                    "engine": cfg.get("engine"),
                    "publicly_accessible": True,
                    "security_group_ids": list(cfg.get("security_group_ids") or []),
                },
                exposure="internet",
            )
        ]


class RdsEncryption:
    meta = meta(
        "ASSAY-RDS-002",
        rationale="Storage encryption covers the data files, backups, replicas and snapshots.",
        impact="Snapshots and backups hold database content in the clear.",
        remediation="Restore from an encrypted snapshot copy; encryption cannot be turned on in place.",
        references=("https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if cfg.get("storage_encrypted"):
            return []
        return [Violation(evidence={"identifier": cfg.get("identifier"), "storage_encrypted": False})]
