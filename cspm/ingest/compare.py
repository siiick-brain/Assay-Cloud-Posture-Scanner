"""Tool comparison against a seeded ground truth: detections, misses, overlaps and false positives."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from cspm.contracts import Finding
from cspm.ingest.core import match_key, resource_key


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """Seeded issues as (resource key, assay rule id) plus resources that are meant to be clean."""

    issues: frozenset[tuple[str, str]]
    secure_resources: frozenset[str]

    @classmethod
    def load(cls, path: Path) -> GroundTruth:
        data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        issues = frozenset((resource_key(i["resource"]), str(i["rule"])) for i in data["issues"])
        secure = frozenset(resource_key(r) for r in data.get("secure_resources", []))
        return cls(issues, secure)


@dataclass(frozen=True, slots=True)
class ToolScore:
    tool: str
    findings: int
    detected: frozenset[tuple[str, str]]
    missed: frozenset[tuple[str, str]]
    false_positives: tuple[Finding, ...]
    beyond_seed: tuple[Finding, ...]


def score_tool(tool: str, findings: Sequence[Finding], truth: GroundTruth) -> ToolScore:
    """Split one tool's findings into seeded detections, false positives and true extras."""
    detected: set[tuple[str, str]] = set()
    fps: list[Finding] = []
    extra: list[Finding] = []
    for f in findings:
        hits = match_key(f) & truth.issues
        if hits:
            detected |= hits
        elif resource_key(f.resource_id) in truth.secure_resources:
            fps.append(f)
        else:
            extra.append(f)
    return ToolScore(tool, len(findings), frozenset(detected), truth.issues - detected, tuple(fps), tuple(extra))


def overlap(scores: Iterable[ToolScore]) -> dict[tuple[str, str], list[str]]:
    """Which tools detected each seeded issue."""
    out: dict[tuple[str, str], list[str]] = {}
    for s in scores:
        for issue in s.detected:
            out.setdefault(issue, []).append(s.tool)
    return out


def unique_detections(scores: Sequence[ToolScore]) -> Mapping[str, frozenset[tuple[str, str]]]:
    """Seeded issues found by exactly one tool, keyed by that tool."""
    who = overlap(scores)
    return {s.tool: frozenset(i for i in s.detected if who[i] == [s.tool]) for s in scores}
