from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cspm.contracts import Severity
from cspm.engine import build_finding
from cspm.scoring import CRITICALITY, EXPOSURE, SENSITIVITY, band_for, score, score_parts
from rules import RULES_BY_ID
from tests.unit.test_rules_cases import CTX, make

SEVERITIES = st.sampled_from(list(Severity))
EXPOSURES = ("none", "internal", "internet")
CRITS = ("low", "medium", "high")
SENS = ("public", "internal", "confidential", "restricted")
TAG_VALUE = st.one_of(st.sampled_from(CRITS + SENS), st.text(max_size=12))


def _tags(crit: str | None, sens: str | None) -> dict[str, str]:
    tags = {}
    if crit is not None:
        tags["criticality"] = crit
    if sens is not None:
        tags["data_sensitivity"] = sens
    return tags


@given(SEVERITIES, st.sampled_from(EXPOSURES), st.none() | TAG_VALUE, st.none() | TAG_VALUE)
def test_score_in_bounds_and_band_consistent(sev: Severity, exp: str, crit: str | None, sens: str | None) -> None:
    value, band = score_parts(sev, exp, _tags(crit, sens))
    assert 0.0 <= value <= 10.0
    assert band == band_for(value)


@given(SEVERITIES, st.sampled_from(CRITS), st.sampled_from(SENS), st.integers(0, 2), st.integers(0, 2))
def test_more_exposure_never_lowers_score(sev: Severity, crit: str, sens: str, a: int, b: int) -> None:
    lo, hi = sorted((a, b))
    tags = _tags(crit, sens)
    assert score_parts(sev, EXPOSURES[lo], tags)[0] <= score_parts(sev, EXPOSURES[hi], tags)[0]


@given(SEVERITIES, st.sampled_from(EXPOSURES), st.sampled_from(SENS), st.integers(0, 2), st.integers(0, 2))
def test_more_criticality_never_lowers_score(sev: Severity, exp: str, sens: str, a: int, b: int) -> None:
    lo, hi = sorted((a, b))
    assert score_parts(sev, exp, _tags(CRITS[lo], sens))[0] <= score_parts(sev, exp, _tags(CRITS[hi], sens))[0]


@given(SEVERITIES, st.sampled_from(EXPOSURES), st.sampled_from(CRITS), st.integers(0, 3), st.integers(0, 3))
def test_more_sensitivity_never_lowers_score(sev: Severity, exp: str, crit: str, a: int, b: int) -> None:
    lo, hi = sorted((a, b))
    assert score_parts(sev, exp, _tags(crit, SENS[lo]))[0] <= score_parts(sev, exp, _tags(crit, SENS[hi]))[0]


def test_tables_are_ordered() -> None:
    assert list(EXPOSURE) == list(EXPOSURES)
    assert list(CRITICALITY.values()) == sorted(CRITICALITY.values())
    assert list(SENSITIVITY.values()) == sorted(SENSITIVITY.values())


@pytest.mark.parametrize(
    ("sev", "exp", "crit", "sens", "expected"),
    [
        (Severity.HIGH, "internet", None, None, (8.5, Severity.HIGH)),
        (Severity.HIGH, "internet", "high", "restricted", (10.0, Severity.CRITICAL)),
        (Severity.CRITICAL, "internal", "low", "public", (8.0, Severity.HIGH)),
        (Severity.MEDIUM, "none", None, None, (5.0, Severity.MEDIUM)),
        (Severity.LOW, "none", "low", "public", (1.0, Severity.LOW)),
        (Severity.INFO, "internet", "high", "restricted", (0.0, Severity.INFO)),
    ],
)
def test_worked_examples(
    sev: Severity, exp: str, crit: str | None, sens: str | None, expected: tuple[float, Severity]
) -> None:
    assert score_parts(sev, exp, _tags(crit, sens)) == expected


def test_band_edges() -> None:
    assert band_for(9.0) is Severity.CRITICAL
    assert band_for(8.9) is Severity.HIGH
    assert band_for(7.0) is Severity.HIGH
    assert band_for(4.0) is Severity.MEDIUM
    assert band_for(3.9) is Severity.LOW
    assert band_for(0.1) is Severity.LOW
    assert band_for(0.0) is Severity.INFO


def test_tag_values_are_case_insensitive_and_unknown_uses_default() -> None:
    assert score_parts(Severity.MEDIUM, "none", {"criticality": " HIGH "})[0] == 6.0
    assert score_parts(Severity.MEDIUM, "none", {"criticality": "huge"})[0] == 5.0


def test_unknown_exposure_rejected() -> None:
    with pytest.raises(ValueError, match="unknown exposure"):
        score_parts(Severity.HIGH, "public", {})


def test_score_reads_resource_tags() -> None:
    rule = RULES_BY_ID["ASSAY-S3-003"]
    res = make("aws.s3.bucket", tags={"data_sensitivity": "restricted"}, encryption=None)
    (v,) = rule.evaluate(res, CTX)
    finding = build_finding(rule, res, v, CTX)
    assert score(finding, res, "none") == (6.0, Severity.MEDIUM)
    assert finding.score == 6.0
