"""Rule classes and the registry keyed by rule ID and by resource type."""

from __future__ import annotations

from types import MappingProxyType

from cspm.contracts.rule import Rule
from rules.aws_iam import (
    ConsoleUserNoMfa,
    OldAccessKey,
    PolicyFullAdmin,
    PolicyServiceWildcard,
    RoleWildcardTrust,
    RootAccessKeys,
    UserDirectAdmin,
    WeakPasswordPolicy,
)
from rules.aws_keys_logs import (
    CertExpiring,
    CertWeakCrypto,
    KmsRotation,
    KmsWildcardPolicy,
    NoMultiRegionTrail,
    SecretRotationAge,
    TrailLogValidation,
)
from rules.aws_network import SgAllTrafficOpen, SgDatabaseOpen, SgRdpOpen, SgSshOpen
from rules.aws_storage import (
    EbsEncryptionByDefault,
    EbsVolumeEncryption,
    RdsEncryption,
    RdsPublic,
    S3AccessLogging,
    S3BlockPublicAccess,
    S3DefaultEncryption,
    S3PublicRead,
    S3Versioning,
)
from rules.azure import BlobContainerPublic, DiskEncryptionOff, KeyVaultPurgeProtection, NsgAnyAny, StorageHttpAllowed

ALL_RULES: tuple[Rule, ...] = (
    S3PublicRead(),
    S3BlockPublicAccess(),
    S3DefaultEncryption(),
    S3Versioning(),
    S3AccessLogging(),
    SgSshOpen(),
    SgRdpOpen(),
    SgDatabaseOpen(),
    SgAllTrafficOpen(),
    EbsVolumeEncryption(),
    EbsEncryptionByDefault(),
    RdsPublic(),
    RdsEncryption(),
    PolicyFullAdmin(),
    PolicyServiceWildcard(),
    UserDirectAdmin(),
    ConsoleUserNoMfa(),
    OldAccessKey(),
    RoleWildcardTrust(),
    RootAccessKeys(),
    WeakPasswordPolicy(),
    NoMultiRegionTrail(),
    TrailLogValidation(),
    KmsRotation(),
    KmsWildcardPolicy(),
    SecretRotationAge(),
    CertExpiring(),
    CertWeakCrypto(),
    BlobContainerPublic(),
    StorageHttpAllowed(),
    NsgAnyAny(),
    KeyVaultPurgeProtection(),
    DiskEncryptionOff(),
)


def _by_type() -> dict[str, tuple[Rule, ...]]:
    index: dict[str, list[Rule]] = {}
    for rule in ALL_RULES:
        for rtype in rule.meta.resource_types:
            index.setdefault(rtype, []).append(rule)
    return {k: tuple(v) for k, v in index.items()}


RULES_BY_ID = MappingProxyType({r.meta.id: r for r in ALL_RULES})
RULES_BY_TYPE = MappingProxyType(_by_type())


def rules_for_type(resource_type: str) -> tuple[Rule, ...]:
    """Rules that apply to one resource type; empty for types no rule covers."""
    return RULES_BY_TYPE.get(resource_type, ())


__all__ = ["ALL_RULES", "RULES_BY_ID", "RULES_BY_TYPE", "rules_for_type"]
