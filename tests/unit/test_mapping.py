from __future__ import annotations

import re
from pathlib import Path

import pytest

from cspm import mapping
from cspm.contracts import RULE_IDS
from cspm.mapping import MIN_FAMILIES, Framework, MappingRow, controls_for, coverage_markdown, load_frameworks, validate

ROOT = Path(__file__).resolve().parents[2]
FAMILIES = {"cis-aws", "nist", "iso-27001", "soc2", "nis2", "iec-62443-4-1", "cra"}
COMPLIANCE_CLAIM = re.compile(r"\b(complies|compliant|certified|certifies|satisfies|meets the requirement)\b", re.I)


def test_seven_framework_families_present() -> None:
    assert {fw.family for fw in load_frameworks()} == FAMILIES


def test_every_mapped_identifier_exists_in_local_list() -> None:
    for fw in load_frameworks():
        listed = set(fw.identifiers)
        missing = [m.control_id for m in fw.mappings if m.control_id not in listed]
        assert not missing, f"{fw.key}: {missing}"


def test_every_rule_maps_to_at_least_three_frameworks() -> None:
    for rule in RULE_IDS:
        families = {fw.family for fw in load_frameworks() for m in fw.mappings if m.rule_id == rule.id}
        assert len(families) >= MIN_FAMILIES, rule.id


def test_rationales_are_single_lines_without_claims() -> None:
    for fw in load_frameworks():
        for m in fw.mappings:
            assert m.rationale.strip() and "\n" not in m.rationale
            assert len(m.rationale) <= 160, m.rationale
            assert not COMPLIANCE_CLAIM.search(m.rationale), m.rationale


def test_identifier_labels_are_short() -> None:
    for fw in load_frameworks():
        for label in fw.labels.values():
            assert len(label.split()) <= 5, label
    cis = next(fw for fw in load_frameworks() if fw.family == "cis-aws")
    assert cis.labels == {}


def test_validate_is_clean_and_catches_problems() -> None:
    assert validate() == []
    bad = Framework(
        key="x",
        name="X",
        family="x",
        note="",
        identifiers=("A",),
        labels={},
        mappings=(MappingRow("ASSAY-NOPE", "A", "r"), MappingRow("ASSAY-S3-001", "B", " ")),
    )
    problems = validate([bad])
    assert any("unknown rule" in p for p in problems)
    assert any("unknown identifier" in p for p in problems)
    assert any("no rationale" in p for p in problems)
    assert any("need 3" in p for p in problems)


def test_controls_for_unknown_rule_is_empty() -> None:
    assert controls_for("ASSAY-NOPE") == []
    assert controls_for("ASSAY-S3-001")


def test_coverage_report_is_current() -> None:
    committed = (ROOT / "docs" / "mapping-coverage.md").read_text(encoding="utf-8")
    assert committed == coverage_markdown(), "run: python -m cspm.mapping"


def test_coverage_report_sections() -> None:
    text = coverage_markdown()
    for fw in load_frameworks():
        assert f"## {fw.name}" in text
    assert "Controls with no rule" in text
    assert "not a compliance" in text


def test_main_writes_and_checks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "cov.md"
    assert mapping.main(["--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == coverage_markdown()
    assert mapping.main(["--check"]) == 0


def test_main_reports_problems(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(mapping, "validate", lambda frameworks=None: ["boom"])
    assert mapping.main(["--check"]) == 1
    assert mapping.main(["--out", str(tmp_path / "x.md")]) == 1
    assert not (tmp_path / "x.md").exists()


def test_mappings_dir_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CSPM_MAPPINGS_DIR", str(tmp_path))
    assert mapping.mappings_dir() == tmp_path
    assert load_frameworks(tmp_path) == ()
