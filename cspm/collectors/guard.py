"""Safety checks shared by the collectors: the read-only allowlist hook, endpoint refusal and the live gate."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

ALLOWLIST_PATH = Path(__file__).resolve().parents[1] / "live" / "allowlist.yaml"
EMULATOR_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1", "moto"})
LIVE_ENV = "CSPM_ALLOW_LIVE"


class BlockedOperationError(RuntimeError):
    """Raised before signing when an AWS call is not on the read-only allowlist."""


class EndpointRefusedError(RuntimeError):
    """Raised when emulator or fixture mode is pointed at a host that is not the local emulator."""


class LiveModeRefusedError(RuntimeError):
    """Raised when live mode is requested without both opt-in switches."""


@dataclass(frozen=True, slots=True)
class Allowlist:
    prefixes: tuple[str, ...]
    deny: frozenset[str]
    operations: frozenset[str]

    def permits(self, service: str, operation: str) -> bool:
        key = f"{service}:{operation}"
        return key in self.operations and operation.startswith(self.prefixes) and key not in self.deny


@lru_cache(maxsize=4)
def load_allowlist(path: Path = ALLOWLIST_PATH) -> Allowlist:
    """Parse the frozen allowlist file once per path."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    ops = frozenset(f"{svc}:{op}" for svc, names in raw["operations"].items() for op in names)
    return Allowlist(tuple(raw["allowed_prefixes"]), frozenset(raw["deny"]), ops)


def enforce_allowlist(model: Any = None, **_: Any) -> None:
    """botocore before-call handler. Raising here stops the request before it is signed or sent."""
    if model is None:
        raise BlockedOperationError("operation model missing, refusing the call")
    service = model.service_model.service_name
    operation = model.name
    if not load_allowlist().permits(service, operation):
        raise BlockedOperationError(f"{service}:{operation} is not on the read-only allowlist")


def check_emulator_endpoint(endpoint: str) -> str:
    """Return the endpoint if its host is the local emulator, else raise."""
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or host not in EMULATOR_HOSTS:
        raise EndpointRefusedError(f"refusing endpoint {endpoint!r}: only {sorted(EMULATOR_HOSTS)} are allowed")
    return endpoint


def check_live_allowed(live_flag: bool = True) -> None:
    """Live scans need the --live flag and CSPM_ALLOW_LIVE=1 together."""
    if not live_flag or os.environ.get(LIVE_ENV) != "1":
        raise LiveModeRefusedError(f"live mode needs --live and {LIVE_ENV}=1")
