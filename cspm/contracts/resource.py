"""Normalized resource model shared by collectors, rules and reports. Frozen at contracts-v1."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Provider(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    TERRAFORM = "terraform"


@dataclass(frozen=True, slots=True)
class Resource:
    """One cloud resource after normalization.

    `type` uses the dotted names in cspm.contracts.rule_ids.RESOURCE_TYPES.
    `config` holds provider fields after collectors flatten them; rules read only this.
    Account-wide settings are modelled as one resource per account and region.
    """

    id: str
    type: str
    provider: Provider
    region: str
    config: Mapping[str, Any] = field(default_factory=dict)
    tags: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "provider": self.provider.value,
            "region": self.region,
            "config": dict(self.config),
            "tags": dict(self.tags),
        }
