"""Azure collector. Reads ARM-shaped JSON fixtures; the live SDK path is Not verified."""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from cspm.collectors.guard import check_live_allowed
from cspm.contracts import Provider, Resource, ScanMode

STORAGE_ACCOUNT = "microsoft.storage/storageaccounts"
CONTAINER = "microsoft.storage/storageaccounts/blobservices/containers"
NSG = "microsoft.network/networksecuritygroups"
VAULT = "microsoft.keyvault/vaults"
DISK = "microsoft.compute/disks"


class FixtureError(ValueError):
    """Raised for fixture files that are missing the synthetic label or are malformed."""


def _props(item: dict[str, Any]) -> dict[str, Any]:
    props = item.get("properties") or {}
    return props if isinstance(props, dict) else {}


def _storage_account(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    p = _props(item)
    return "azure.storage.account", {
        "name": item["name"],
        "https_only": bool(p.get("supportsHttpsTrafficOnly", True)),
        "min_tls_version": str(p.get("minimumTlsVersion", "TLS1_0")),
        "allow_blob_public_access": bool(p.get("allowBlobPublicAccess", False)),
    }


def _container(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    # ARM container IDs look like .../storageAccounts/<account>/blobServices/default/containers/<name>.
    parts = str(item["id"]).split("/")
    account = parts[parts.index("storageAccounts") + 1] if "storageAccounts" in parts else ""
    access = str(_props(item).get("publicAccess") or "None")
    return "azure.storage.container", {"name": item["name"], "account": account, "public_access": access}


def _nsg(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    rules = []
    for rule in _props(item).get("securityRules", []):
        rp = _props(rule)
        rules.append(
            {
                "name": rule.get("name", ""),
                "direction": rp.get("direction", ""),
                "access": rp.get("access", ""),
                "protocol": rp.get("protocol", ""),
                "source_address_prefix": rp.get("sourceAddressPrefix", ""),
                "destination_port_range": rp.get("destinationPortRange", ""),
                "priority": rp.get("priority", 0),
            }
        )
    return "azure.network.nsg", {"name": item["name"], "security_rules": rules}


def _vault(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    p = _props(item)
    return "azure.keyvault.vault", {
        "name": item["name"],
        "purge_protection": bool(p.get("enablePurgeProtection", False)),
        "soft_delete": bool(p.get("enableSoftDelete", False)),
    }


def _disk(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    p = _props(item)
    enc = p.get("encryption") or {}
    enc_type = enc.get("type") if isinstance(enc, dict) else None
    settings = p.get("encryptionSettingsCollection") or {}
    enabled = bool(enc_type) or bool(settings.get("enabled", False))
    return "azure.compute.disk", {"name": item["name"], "encryption_type": enc_type, "encryption_enabled": enabled}


NORMALIZERS: dict[str, Callable[[dict[str, Any]], tuple[str, dict[str, Any]]]] = {
    STORAGE_ACCOUNT: _storage_account,
    CONTAINER: _container,
    NSG: _nsg,
    VAULT: _vault,
    DISK: _disk,
}


def normalize(items: Iterable[dict[str, Any]]) -> list[Resource]:
    """Turn ARM resource dicts into contract resources, skipping types no rule reads."""
    out = []
    for item in items:
        fn = NORMALIZERS.get(str(item.get("type", "")).lower())
        if fn is None:
            continue
        rtype, config = fn(item)
        tags = {str(k): str(v) for k, v in (item.get("tags") or {}).items()}
        out.append(Resource(str(item["id"]), rtype, Provider.AZURE, str(item.get("location", "global")), config, tags))
    return out


def load_fixtures(source: str | Path) -> list[dict[str, Any]]:
    """Read one JSON file or every JSON file in a folder. Each must carry "synthetic": true."""
    path = Path(source)
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    if not files:
        raise FixtureError(f"no fixture files under {path}")
    items: list[dict[str, Any]] = []
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        # Only synthetic data belongs in the repo, so unlabelled exports are refused.
        if not isinstance(data, dict) or data.get("synthetic") is not True:
            raise FixtureError(f"{f.name} is not labelled synthetic")
        resources = data.get("resources")
        if not isinstance(resources, list):
            raise FixtureError(f"{f.name} has no resources list")
        items.extend(resources)
    return items


def _live_items() -> list[dict[str, Any]]:
    """Not verified: no Azure account is used in this project."""
    sub = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub:
        raise RuntimeError("live Azure mode reads the subscription only from AZURE_SUBSCRIPTION_ID")
    identity = importlib.import_module("azure.identity")
    cred = identity.EnvironmentCredential()
    storage = importlib.import_module("azure.mgmt.storage").StorageManagementClient(cred, sub)
    network = importlib.import_module("azure.mgmt.network").NetworkManagementClient(cred, sub)
    vaults = importlib.import_module("azure.mgmt.keyvault").KeyVaultManagementClient(cred, sub)
    compute = importlib.import_module("azure.mgmt.compute").ComputeManagementClient(cred, sub)
    items: list[dict[str, Any]] = []
    for acct in storage.storage_accounts.list():
        items.append(_arm(acct, STORAGE_ACCOUNT))
        group = str(acct.id).split("/")[4]
        for cont in storage.blob_containers.list(group, acct.name):
            items.append(_arm(cont, CONTAINER))
    items += [_arm(n, NSG) for n in network.network_security_groups.list_all()]
    items += [_arm(v, VAULT) for v in vaults.vaults.list_by_subscription()]
    items += [_arm(d, DISK) for d in compute.disks.list()]
    return items


def _arm(model: Any, rtype: str) -> dict[str, Any]:
    """SDK models flatten properties; put them back under "properties" so one normalizer serves both."""
    raw: dict[str, Any] = model.as_dict(keep_readonly=True)
    top: dict[str, Any] = {k: raw.pop(k) for k in ("id", "name", "location", "tags") if k in raw}
    nested = raw.pop("properties", None)
    if isinstance(nested, dict):
        raw = {**nested, **raw}
    rules = raw.get("security_rules")
    if isinstance(rules, list):
        raw["security_rules"] = [{"name": r.get("name"), "properties": _camel(r)} for r in rules]
    return {**top, "type": rtype, "properties": _camel(raw)}


def _camel(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in d.items():
        head, *rest = key.split("_")
        out[head + "".join(w.title() for w in rest)] = value
    # The SDK names this field differently from ARM JSON.
    if "enableHttpsTrafficOnly" in out:
        out["supportsHttpsTrafficOnly"] = out.pop("enableHttpsTrafficOnly")
    return out


def collect_azure(*, mode: ScanMode, source: str | None) -> list[Resource]:
    """Collect Azure resources from synthetic fixtures, or through the SDK when live mode is unlocked."""
    if mode is ScanMode.LIVE:
        check_live_allowed()
        return normalize(_live_items())
    if not source:
        raise FixtureError("Azure fixture mode needs a source path")
    return normalize(load_fixtures(source))
