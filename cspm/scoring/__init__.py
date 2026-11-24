"""Risk score from 0 to 10 and a severity band. See docs/scoring.md for the table."""

from __future__ import annotations

from collections.abc import Mapping

from cspm.contracts.finding import Finding, Severity
from cspm.contracts.resource import Resource
from cspm.contracts.rule_ids import EXPOSURE_LEVELS

BASE: Mapping[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}
EXPOSURE: Mapping[str, float] = {"none": 0.0, "internal": 0.5, "internet": 1.0}
CRITICALITY: Mapping[str, float] = {"low": -1.0, "medium": 0.0, "high": 1.0}
SENSITIVITY: Mapping[str, float] = {"public": -0.5, "internal": 0.0, "confidential": 0.5, "restricted": 1.0}
DEFAULT_CRITICALITY = "medium"
DEFAULT_SENSITIVITY = "internal"

BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
)


def _tag(tags: Mapping[str, str], name: str, table: Mapping[str, float], default: str) -> float:
    # Unknown tag values fall back to the default so a typo never hides or inflates risk.
    value = str(tags.get(name, default)).strip().lower()
    return table.get(value, table[default])


def band_for(value: float) -> Severity:
    """Map a score to its band: critical >= 9, high >= 7, medium >= 4, low > 0, info 0."""
    for floor, severity in BANDS:
        if value >= floor:
            return severity
    return Severity.LOW if value > 0 else Severity.INFO


def score_parts(severity: Severity, exposure: str, tags: Mapping[str, str]) -> tuple[float, Severity]:
    """Score from the raw inputs; `score` wraps this for the module interface."""
    if exposure not in EXPOSURE_LEVELS:
        raise ValueError(f"unknown exposure {exposure!r}, expected one of {EXPOSURE_LEVELS}")
    base = BASE[severity]
    # Informational findings carry no risk, so context must not lift them into a real band.
    if base == 0.0:
        return 0.0, Severity.INFO
    raw = (
        base
        + EXPOSURE[exposure]
        + _tag(tags, "criticality", CRITICALITY, DEFAULT_CRITICALITY)
        + _tag(tags, "data_sensitivity", SENSITIVITY, DEFAULT_SENSITIVITY)
    )
    value = round(min(10.0, max(0.0, raw)), 1)
    return value, band_for(value)


def score(finding: Finding, resource: Resource, exposure: str) -> tuple[float, Severity]:
    """Score a finding on its resource for the exposure the rule reported."""
    return score_parts(finding.severity_base, exposure, resource.tags)


__all__ = ["band_for", "score", "score_parts"]
