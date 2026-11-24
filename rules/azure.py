"""Azure storage, network, Key Vault and disk rules."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cspm.contracts.resource import Resource
from cspm.contracts.rule import ScanContext, Violation
from rules._base import meta

_ANY_SOURCE = {"*", "internet", "any", "0.0.0.0/0", "::/0"}
_ANY_PORT = {"*", "0-65535", "any"}


class BlobContainerPublic:
    meta = meta(
        "ASSAY-AZ-STG-001",
        rationale="Blob or Container public access lets anyone with the URL read blobs without a key.",
        impact="Stored files can be downloaded anonymously, and Container level also allows listing.",
        remediation="Set the container access level to Private and turn off blob public access on the account.",
        references=("https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        level = str(cfg.get("public_access") or "None")
        if level not in ("Blob", "Container"):
            return []
        # The account setting overrides the container level, so a blocked account means no exposure.
        for other in ctx.inventory:
            same = other.type == "azure.storage.account" and other.config.get("name") == cfg.get("account")
            if same and other.config.get("allow_blob_public_access") is False:
                return []
        evidence = {"container": cfg.get("name"), "account": cfg.get("account"), "public_access": level}
        return [Violation(evidence=evidence, exposure="internet")]


class StorageHttpAllowed:
    meta = meta(
        "ASSAY-AZ-STG-002",
        rationale="Accepting plain HTTP lets requests and keys travel without encryption.",
        impact="Anyone on the path can read or change data and capture SAS tokens.",
        remediation="Turn on secure transfer required and set the minimum TLS version to 1.2.",
        references=("https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if cfg.get("https_only"):
            return []
        evidence = {"account": cfg.get("name"), "https_only": False, "min_tls_version": cfg.get("min_tls_version")}
        return [Violation(evidence=evidence, exposure="internet")]


def _any_any(rule: Mapping[str, Any]) -> bool:
    return (
        str(rule.get("direction", "")).lower() == "inbound"
        and str(rule.get("access", "")).lower() == "allow"
        and str(rule.get("source_address_prefix", "")).lower() in _ANY_SOURCE
        and str(rule.get("destination_port_range", "")).lower() in _ANY_PORT
    )


class NsgAnyAny:
    meta = meta(
        "ASSAY-AZ-NSG-001",
        rationale="An inbound allow for every port from any source removes network filtering for the subnet or NIC.",
        impact="Every listening service on attached machines is reachable from the internet.",
        remediation="Delete the rule and allow only the ports and sources the workload needs.",
        references=("https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        names = [str(r.get("name")) for r in resource.config.get("security_rules") or [] if _any_any(r)]
        if not names:
            return []
        return [Violation(evidence={"nsg": resource.config.get("name"), "rules": names}, exposure="internet")]


class KeyVaultPurgeProtection:
    meta = meta(
        "ASSAY-AZ-KV-001",
        rationale="Purge protection stops a deleted vault or key from being destroyed before retention ends.",
        impact="An attacker or mistake can permanently destroy keys and the data they protect.",
        remediation="Enable purge protection on the vault; it cannot be turned off afterwards.",
        references=("https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if cfg.get("purge_protection"):
            return []
        evidence = {"vault": cfg.get("name"), "purge_protection": False, "soft_delete": bool(cfg.get("soft_delete"))}
        return [Violation(evidence=evidence)]


class DiskEncryptionOff:
    meta = meta(
        "ASSAY-AZ-DSK-001",
        rationale="A disk without encryption holds its data in the clear on the storage backend and in snapshots.",
        impact="Copied snapshots or exported disks expose the whole volume.",
        remediation="Enable encryption at rest with platform or customer managed keys.",
        references=("https://learn.microsoft.com/azure/virtual-machines/disk-encryption",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if cfg.get("encryption_enabled"):
            return []
        evidence = {"disk": cfg.get("name"), "encryption_enabled": False, "encryption_type": cfg.get("encryption_type")}
        return [Violation(evidence=evidence)]
