"""Stable rule IDs, resource types and exposure levels. Frozen at contracts-v1."""

from __future__ import annotations

from dataclasses import dataclass

from cspm.contracts.finding import Severity

EXPOSURE_LEVELS: tuple[str, ...] = ("none", "internal", "internet")

RESOURCE_TYPES: tuple[str, ...] = (
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
    "azure.storage.account",
    "azure.storage.container",
    "azure.network.nsg",
    "azure.keyvault.vault",
    "azure.compute.disk",
)


@dataclass(frozen=True, slots=True)
class RuleId:
    id: str
    resource_type: str
    severity_base: Severity
    summary: str


RULE_IDS: tuple[RuleId, ...] = (
    RuleId("ASSAY-S3-001", "aws.s3.bucket", Severity.HIGH, "Bucket readable by the public through ACL or policy"),
    RuleId("ASSAY-S3-002", "aws.s3.bucket", Severity.MEDIUM, "Bucket Block Public Access not fully on"),
    RuleId("ASSAY-S3-003", "aws.s3.bucket", Severity.MEDIUM, "Bucket has no default encryption configuration"),
    RuleId("ASSAY-S3-004", "aws.s3.bucket", Severity.LOW, "Bucket versioning not enabled"),
    RuleId("ASSAY-S3-005", "aws.s3.bucket", Severity.LOW, "Bucket access logging not enabled"),
    RuleId("ASSAY-EC2-001", "aws.ec2.security_group", Severity.HIGH, "SSH open to the internet"),
    RuleId("ASSAY-EC2-002", "aws.ec2.security_group", Severity.HIGH, "RDP open to the internet"),
    RuleId("ASSAY-EC2-003", "aws.ec2.security_group", Severity.HIGH, "Database port open to the internet"),
    RuleId("ASSAY-EC2-004", "aws.ec2.security_group", Severity.CRITICAL, "All traffic open to the internet"),
    RuleId("ASSAY-EC2-005", "aws.ec2.volume", Severity.MEDIUM, "EBS volume not encrypted"),
    RuleId("ASSAY-EC2-006", "aws.ec2.region_settings", Severity.LOW, "EBS encryption by default off"),
    RuleId("ASSAY-RDS-001", "aws.rds.instance", Severity.HIGH, "Database instance publicly accessible"),
    RuleId("ASSAY-RDS-002", "aws.rds.instance", Severity.MEDIUM, "Database storage not encrypted"),
    RuleId("ASSAY-IAM-001", "aws.iam.policy", Severity.CRITICAL, "Policy allows every action on every resource"),
    RuleId("ASSAY-IAM-002", "aws.iam.policy", Severity.MEDIUM, "Policy grants a service-wide action wildcard"),
    RuleId("ASSAY-IAM-003", "aws.iam.user", Severity.HIGH, "User has administrator access attached directly"),
    RuleId("ASSAY-IAM-004", "aws.iam.user", Severity.HIGH, "Console user without MFA"),
    RuleId("ASSAY-IAM-005", "aws.iam.user", Severity.MEDIUM, "Active access key older than 90 days"),
    RuleId("ASSAY-IAM-006", "aws.iam.role", Severity.HIGH, "Trust policy allows a wildcard principal"),
    RuleId("ASSAY-IAM-007", "aws.iam.account", Severity.CRITICAL, "Root user has active access keys"),
    RuleId("ASSAY-IAM-008", "aws.iam.account", Severity.LOW, "Password policy missing or weak"),
    RuleId("ASSAY-LOG-001", "aws.cloudtrail.account", Severity.HIGH, "No multi-region trail is logging"),
    RuleId("ASSAY-LOG-002", "aws.cloudtrail.trail", Severity.LOW, "Trail log file validation off"),
    RuleId("ASSAY-KMS-001", "aws.kms.key", Severity.MEDIUM, "Customer managed key rotation off"),
    RuleId("ASSAY-KMS-002", "aws.kms.key", Severity.HIGH, "Key policy allows a wildcard principal"),
    RuleId("ASSAY-SEC-001", "aws.secretsmanager.secret", Severity.MEDIUM, "Secret not rotated in 90 days"),
    RuleId("ASSAY-ACM-001", "aws.acm.certificate", Severity.MEDIUM, "Certificate expires within 30 days"),
    RuleId("ASSAY-ACM-002", "aws.acm.certificate", Severity.MEDIUM, "Certificate uses a weak key or signature"),
    RuleId("ASSAY-AZ-STG-001", "azure.storage.container", Severity.HIGH, "Blob container allows public access"),
    RuleId("ASSAY-AZ-STG-002", "azure.storage.account", Severity.MEDIUM, "Storage account accepts plain HTTP"),
    RuleId("ASSAY-AZ-NSG-001", "azure.network.nsg", Severity.CRITICAL, "NSG allows any port from any source"),
    RuleId("ASSAY-AZ-KV-001", "azure.keyvault.vault", Severity.MEDIUM, "Key Vault purge protection off"),
    RuleId("ASSAY-AZ-DSK-001", "azure.compute.disk", Severity.MEDIUM, "Managed disk encryption off"),
)

RULE_ID_SET: frozenset[str] = frozenset(r.id for r in RULE_IDS)
