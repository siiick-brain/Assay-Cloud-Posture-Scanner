"""Rule interface. Frozen at contracts-v1."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from cspm.contracts.finding import ScanMode, Severity
from cspm.contracts.resource import Resource


@dataclass(frozen=True, slots=True)
class RuleMeta:
    id: str
    title: str
    resource_types: tuple[str, ...]
    severity_base: Severity
    rationale: str
    impact: str
    remediation: str
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a rule may read besides the resource itself.

    Rules use `now` instead of the system clock. `inventory` lets account-level
    rules look at other resources, for example a trail check across regions.
    """

    now: datetime
    mode: ScanMode
    inventory: Sequence[Resource] = ()
    settings: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Violation:
    """Evidence for one failed check. Values must already be safe to store."""

    evidence: Mapping[str, Any]
    exposure: str = "none"


@runtime_checkable
class Rule(Protocol):
    meta: RuleMeta

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        """Return an empty list when the resource passes."""
        ...
