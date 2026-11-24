"""KMS rotation and Secrets Manager age checks using read-only calls from cspm/live/allowlist.yaml."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cspm.contracts.rule import Violation

SECRET_MAX_AGE_DAYS = 90
_SKIP_KEY_STATES = frozenset({"PendingDeletion", "PendingReplicaDeletion"})


def check_kms_rotation(kms_client: Any) -> list[Violation]:
    """Flag enabled customer managed symmetric keys whose rotation is off."""
    out: list[Violation] = []
    for page in kms_client.get_paginator("list_keys").paginate():
        for entry in page["Keys"]:
            meta = kms_client.describe_key(KeyId=entry["KeyId"])["KeyMetadata"]
            # AWS rotates its own keys and only symmetric customer keys support automatic rotation.
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                continue
            if meta.get("KeyState") in _SKIP_KEY_STATES:
                continue
            status = kms_client.get_key_rotation_status(KeyId=entry["KeyId"])
            if not status.get("KeyRotationEnabled", False):
                evidence = {"check": "kms_rotation_off", "severity": "medium", "key_id": meta["KeyId"],
                            "key_state": meta.get("KeyState")}
                out.append(Violation(evidence=evidence))
    return out


def check_secret_age(secrets_client: Any, now: datetime, *, max_age_days: int = SECRET_MAX_AGE_DAYS) -> list[Violation]:
    """Flag secrets whose last rotation, or creation when never rotated, is older than `max_age_days`."""
    out: list[Violation] = []
    for page in secrets_client.get_paginator("list_secrets").paginate():
        for item in page["SecretList"]:
            last: datetime | None = item.get("LastRotatedDate")
            reference = last or item.get("CreatedDate")
            if reference is None:
                continue
            age = (now - reference).days
            if age > max_age_days:
                evidence = {"check": "secret_not_rotated", "severity": "medium", "name": item["Name"],
                            "age_days": age, "max_age_days": max_age_days,
                            "rotation_enabled": bool(item.get("RotationEnabled", False)),
                            "last_rotated": last.isoformat() if last else None}
                out.append(Violation(evidence=evidence))
    return out
