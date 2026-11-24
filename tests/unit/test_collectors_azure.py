import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from cspm.collectors import collect
from cspm.collectors.azure import FixtureError, load_fixtures, normalize
from cspm.collectors.guard import LiveModeRefusedError
from cspm.contracts import Provider, ScanMode

ROOT = Path(__file__).resolve().parents[2]
INSECURE = ROOT / "testbed" / "azure-fixtures" / "insecure"
SECURE = ROOT / "testbed" / "azure-fixtures" / "secure"


def _by_type(source: Path) -> dict[str, Any]:
    rs = collect(Provider.AZURE, mode=ScanMode.FIXTURE, source=str(source))
    assert all(r.provider is Provider.AZURE for r in rs)
    return {r.type: r for r in rs}


def test_insecure_fixtures() -> None:
    rs = _by_type(INSECURE)
    assert set(rs) == {
        "azure.storage.account",
        "azure.storage.container",
        "azure.network.nsg",
        "azure.keyvault.vault",
        "azure.compute.disk",
    }
    assert rs["azure.storage.container"].config == {
        "name": "public-assets",
        "account": "stassayinsecure",
        "public_access": "Container",
    }
    rule = rs["azure.network.nsg"].config["security_rules"][0]
    assert rule["source_address_prefix"] == "*"
    assert rule["destination_port_range"] == "*"
    assert rule["direction"] == "Inbound"
    assert rs["azure.keyvault.vault"].config["purge_protection"] is False
    assert rs["azure.compute.disk"].config == {
        "name": "disk-assay-insecure",
        "encryption_type": None,
        "encryption_enabled": False,
    }
    assert rs["azure.storage.account"].config["https_only"] is True
    assert rs["azure.storage.account"].tags["criticality"] == "high"


def test_secure_fixtures() -> None:
    rs = _by_type(SECURE)
    assert rs["azure.storage.container"].config["public_access"] == "None"
    assert rs["azure.keyvault.vault"].config["purge_protection"] is True
    assert rs["azure.compute.disk"].config["encryption_enabled"] is True
    assert rs["azure.compute.disk"].config["encryption_type"] == "EncryptionAtRestWithPlatformKey"


def test_unlabelled_fixture_refused(tmp_path: Path) -> None:
    (tmp_path / "real.json").write_text(json.dumps({"resources": []}))
    with pytest.raises(FixtureError, match="synthetic"):
        load_fixtures(tmp_path)


def test_fixture_without_resources_refused(tmp_path: Path) -> None:
    f = tmp_path / "x.json"
    f.write_text(json.dumps({"synthetic": True}))
    with pytest.raises(FixtureError, match="resources"):
        load_fixtures(f)


def test_empty_folder_refused(tmp_path: Path) -> None:
    with pytest.raises(FixtureError, match="no fixture"):
        load_fixtures(tmp_path)


def test_fixture_mode_needs_source() -> None:
    with pytest.raises(FixtureError):
        collect(Provider.AZURE, mode=ScanMode.FIXTURE, source=None)


def test_unknown_types_skipped_and_defaults() -> None:
    rs = normalize(
        [
            {"id": "/x/vm", "name": "vm", "type": "Microsoft.Compute/virtualMachines"},
            {"id": "/x/c", "name": "c", "type": "Microsoft.Storage/storageAccounts/blobServices/containers"},
            {"id": "/x/v", "name": "v", "type": "Microsoft.KeyVault/vaults", "properties": None},
        ]
    )
    assert [r.type for r in rs] == ["azure.storage.container", "azure.keyvault.vault"]
    assert rs[0].config == {"name": "c", "account": "", "public_access": "None"}
    assert rs[0].region == "global"
    assert rs[1].config["soft_delete"] is False


def test_live_refused_without_switches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CSPM_ALLOW_LIVE", raising=False)
    with pytest.raises(LiveModeRefusedError):
        collect(Provider.AZURE, mode=ScanMode.LIVE, source=None)


def test_live_needs_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CSPM_ALLOW_LIVE", "1")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    with pytest.raises(RuntimeError, match="AZURE_SUBSCRIPTION_ID"):
        collect(Provider.AZURE, mode=ScanMode.LIVE, source=None)


class _Model:
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data
        self.id = data["id"]
        self.name = data["name"]

    def as_dict(self, keep_readonly: bool = True) -> dict[str, Any]:
        return json.loads(json.dumps(self._data))


SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers"


def _fake_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    acct = _Model(
        {
            "id": f"{SUB}/Microsoft.Storage/storageAccounts/st1",
            "name": "st1",
            "location": "westeurope",
            "tags": {"criticality": "low"},
            "enable_https_traffic_only": False,
            "minimum_tls_version": "TLS1_0",
            "allow_blob_public_access": True,
        }
    )
    cont = _Model(
        {
            "id": f"{SUB}/Microsoft.Storage/storageAccounts/st1/blobServices/default/containers/c1",
            "name": "c1",
            "public_access": "Blob",
        }
    )
    nsg = _Model(
        {
            "id": f"{SUB}/Microsoft.Network/networkSecurityGroups/n1",
            "name": "n1",
            "security_rules": [
                {
                    "name": "r1",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "*",
                    "source_address_prefix": "*",
                    "destination_port_range": "*",
                    "priority": 100,
                }
            ],
        }
    )
    vault = _Model(
        {
            "id": f"{SUB}/Microsoft.KeyVault/vaults/v1",
            "name": "v1",
            "properties": {"enable_purge_protection": None, "enable_soft_delete": True},
        }
    )
    disk = _Model({"id": f"{SUB}/Microsoft.Compute/disks/d1", "name": "d1", "encryption": {"type": None}})

    def ns(**kw: Any) -> types.SimpleNamespace:
        return types.SimpleNamespace(**kw)

    def client(**ops: Any) -> Any:
        return lambda cred, sub: ns(**ops)

    modules = {
        "azure": types.ModuleType("azure"),
        "azure.identity": ns(EnvironmentCredential=object),
        "azure.mgmt.storage": ns(
            StorageManagementClient=client(
                storage_accounts=ns(list=lambda: [acct]), blob_containers=ns(list=lambda g, a: [cont])
            )
        ),
        "azure.mgmt.network": ns(NetworkManagementClient=client(network_security_groups=ns(list_all=lambda: [nsg]))),
        "azure.mgmt.keyvault": ns(KeyVaultManagementClient=client(vaults=ns(list_by_subscription=lambda: [vault]))),
        "azure.mgmt.compute": ns(ComputeManagementClient=client(disks=ns(list=lambda: [disk]))),
    }
    for name, mod in modules.items():
        monkeypatch.setitem(sys.modules, name, mod)


def test_live_path_with_fake_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CSPM_ALLOW_LIVE", "1")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")
    _fake_sdk(monkeypatch)
    rs = {r.type: r for r in collect(Provider.AZURE, mode=ScanMode.LIVE, source=None)}
    assert rs["azure.storage.account"].config == {
        "name": "st1",
        "https_only": False,
        "min_tls_version": "TLS1_0",
        "allow_blob_public_access": True,
    }
    assert rs["azure.storage.container"].config["public_access"] == "Blob"
    assert rs["azure.storage.container"].config["account"] == "st1"
    assert rs["azure.network.nsg"].config["security_rules"][0]["source_address_prefix"] == "*"
    assert rs["azure.keyvault.vault"].config["purge_protection"] is False
    assert rs["azure.keyvault.vault"].config["soft_delete"] is True
    assert rs["azure.compute.disk"].config["encryption_enabled"] is False
