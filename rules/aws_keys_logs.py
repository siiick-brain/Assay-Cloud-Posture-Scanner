"""CloudTrail, KMS, Secrets Manager and ACM rules."""

from __future__ import annotations

import re

from cspm.contracts.resource import Resource
from cspm.contracts.rule import ScanContext, Violation
from rules._base import age_days, meta, parse_time, wildcard_principal_statements

SECRET_MAX_AGE_DAYS = 90
CERT_WARN_DAYS = 30
MIN_RSA_BITS = 2048
_WEAK_SIGNATURES = ("SHA1", "MD5", "MD2")


class NoMultiRegionTrail:
    meta = meta(
        "ASSAY-LOG-001",
        rationale="Only a logging multi-region trail records API activity in every region, including unused ones.",
        impact="Attacker activity in an unwatched region leaves no audit record.",
        remediation="Create one multi-region trail that is logging, ideally an organization trail.",
        references=(
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
        ),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if cfg.get("has_logging_multi_region_trail"):
            return []
        return [
            Violation(
                evidence={"trail_names": list(cfg.get("trail_names") or []), "has_logging_multi_region_trail": False}
            )
        ]


class TrailLogValidation:
    meta = meta(
        "ASSAY-LOG-002",
        rationale="Digest files let you prove log files were not changed or deleted after delivery.",
        impact="An intruder could edit logs to hide their steps without detection.",
        remediation="Enable log file validation on the trail.",
        references=(
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
        ),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        if resource.config.get("log_file_validation"):
            return []
        return [Violation(evidence={"trail": resource.config.get("name"), "log_file_validation": False})]


class KmsRotation:
    meta = meta(
        "ASSAY-KMS-001",
        rationale="Automatic rotation limits how much data any one version of key material protects.",
        impact="Key material stays in use for years, raising the cost of a compromise.",
        remediation="Enable automatic rotation on customer managed symmetric keys.",
        references=("https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        # Rotation exists only for enabled customer managed symmetric keys.
        if cfg.get("manager") != "CUSTOMER" or cfg.get("state", "Enabled") != "Enabled":
            return []
        if cfg.get("key_spec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT" or cfg.get("rotation_enabled"):
            return []
        return [Violation(evidence={"key_id": cfg.get("key_id"), "rotation_enabled": False})]


class KmsWildcardPolicy:
    meta = meta(
        "ASSAY-KMS-002",
        rationale="A key policy open to any principal without conditions lets other accounts use or manage the key.",
        impact="Outsiders may decrypt data protected by the key or schedule it for deletion.",
        remediation="Name the allowed principals or add conditions such as kms:CallerAccount.",
        references=("https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        labels = wildcard_principal_statements(resource.config.get("policy"))
        if not labels:
            return []
        return [
            Violation(evidence={"key_id": resource.config.get("key_id"), "statements": labels}, exposure="internet")
        ]


class SecretRotationAge:
    meta = meta(
        "ASSAY-SEC-001",
        rationale="A secret that has not changed in 90 days has had more time to leak and still works.",
        impact="A leaked credential keeps working long after the leak.",
        remediation="Turn on rotation with a Lambda rotation function and a schedule of 90 days or less.",
        references=("https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        reference = cfg.get("last_rotated") or cfg.get("created")
        age = age_days(reference, ctx.now)
        if age is None or age <= SECRET_MAX_AGE_DAYS:
            return []
        evidence = {
            "secret": cfg.get("name"),
            "days_since_rotation": int(age),
            "rotation_enabled": bool(cfg.get("rotation_enabled")),
        }
        return [Violation(evidence=evidence)]


class CertExpiring:
    meta = meta(
        "ASSAY-ACM-001",
        rationale="A certificate close to expiry will break TLS for clients if renewal fails.",
        impact="Clients see errors or fall back to unsafe behaviour once the certificate expires.",
        remediation="Renew or reissue the certificate and check DNS validation so managed renewal works.",
        references=("https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        not_after = parse_time(cfg.get("not_after"))
        if not_after is None:
            return []
        remaining = -(age_days(not_after, ctx.now) or 0.0)
        if remaining > CERT_WARN_DAYS:
            return []
        evidence = {"domain": cfg.get("domain"), "not_after": cfg.get("not_after"), "days_left": int(remaining)}
        return [Violation(evidence=evidence, exposure="internet")]


class CertWeakCrypto:
    meta = meta(
        "ASSAY-ACM-002",
        rationale="RSA keys under 2048 bits and SHA-1 or MD5 signatures can be broken or forged.",
        impact="An attacker may impersonate the endpoint or read traffic.",
        remediation="Reissue the certificate with RSA 2048 or an EC key and a SHA-256 or stronger signature.",
        references=("https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        problems = []
        key = str(cfg.get("key_algorithm") or "")
        bits = re.fullmatch(r"RSA[_-]?(\d+)", key.upper())
        if bits and int(bits.group(1)) < MIN_RSA_BITS:
            problems.append(f"weak key {key}")
        sig = str(cfg.get("signature_algorithm") or "")
        if any(s in sig.upper().replace("-", "") for s in _WEAK_SIGNATURES):
            problems.append(f"weak signature {sig}")
        if not problems:
            return []
        return [Violation(evidence={"domain": cfg.get("domain"), "problems": problems}, exposure="internet")]
