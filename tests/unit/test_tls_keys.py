from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3
import pytest
import yaml
from moto import mock_aws

from cspm.tls import check_kms_rotation, check_secret_age

ALLOWLIST = yaml.safe_load((Path(__file__).resolve().parents[2] / "cspm" / "live" / "allowlist.yaml").read_text())
REGION = "us-east-1"


@pytest.fixture
def aws(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                        "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(name, value)
    with mock_aws():
        yield


def _record_calls(client: Any, service: str) -> list[str]:
    """Track every operation the checker sends so we can compare it with the allowlist."""
    seen: list[str] = []

    def hook(model: Any, **_: Any) -> None:
        seen.append(model.name)

    client.meta.events.register("before-call", hook)
    return seen


def _assert_allowlisted(service: str, ops: list[str]) -> None:
    assert ops
    for op in ops:
        assert op in ALLOWLIST["operations"][service], op
        assert f"{service}:{op}" not in ALLOWLIST["deny"]


def test_kms_rotation(aws: None) -> None:
    kms = boto3.client("kms", region_name=REGION)
    on = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=on)
    off = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")
    gone = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.schedule_key_deletion(KeyId=gone, PendingWindowInDays=7)
    seen = _record_calls(kms, "kms")
    found = check_kms_rotation(kms)
    assert [v.evidence["key_id"] for v in found] == [off]
    assert found[0].evidence["check"] == "kms_rotation_off"
    _assert_allowlisted("kms", seen)


def test_secret_age(aws: None) -> None:
    sm = boto3.client("secretsmanager", region_name=REGION)
    sm.create_secret(Name="app/db", SecretString="x")
    seen = _record_calls(sm, "secretsmanager")
    now = datetime.now(UTC)
    assert check_secret_age(sm, now) == []
    later = check_secret_age(sm, now + timedelta(days=120))
    assert len(later) == 1
    ev = later[0].evidence
    assert ev["name"] == "app/db"
    assert ev["last_rotated"] is None
    assert ev["age_days"] >= 119
    _assert_allowlisted("secretsmanager", seen)


class _FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    def paginate(self) -> list[dict[str, Any]]:
        return self._pages


class _FakeSecrets:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self._items = items

    def get_paginator(self, name: str) -> _FakePaginator:
        assert name == "list_secrets"
        return _FakePaginator([{"SecretList": self._items}])


def test_secret_age_prefers_last_rotated() -> None:
    now = datetime(2026, 11, 23, tzinfo=UTC)
    items = [
        {"Name": "fresh", "CreatedDate": now - timedelta(days=400), "LastRotatedDate": now - timedelta(days=10),
         "RotationEnabled": True},
        {"Name": "stale", "CreatedDate": now - timedelta(days=400), "LastRotatedDate": now - timedelta(days=100)},
        {"Name": "nodates"},
    ]
    found = check_secret_age(_FakeSecrets(items), now, max_age_days=90)
    assert [v.evidence["name"] for v in found] == ["stale"]
    assert found[0].evidence["last_rotated"] == (now - timedelta(days=100)).isoformat()
