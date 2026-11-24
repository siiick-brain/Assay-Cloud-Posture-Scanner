"""Tests for cspm.ingest.xccdf against the recorded OpenSCAP runs."""

from __future__ import annotations

from pathlib import Path

import pytest

from cspm.contracts.finding import Severity, Source
from cspm.ingest.xccdf import count_results, parse_xccdf

RECORDED = Path(__file__).resolve().parents[2] / "fixtures" / "recorded" / "openscap"
BEFORE = RECORDED / "before-results.xml"
AFTER = RECORDED / "after-results.xml"


def test_before_counts_match_recorded_run() -> None:
    assert count_results(BEFORE) == {"pass": 129, "fail": 9, "notapplicable": 270, "notselected": 240}


def test_after_counts_match_recorded_run() -> None:
    assert count_results(AFTER) == {"pass": 135, "fail": 3, "notapplicable": 270, "notselected": 240}


def test_one_finding_per_failed_rule() -> None:
    findings = parse_xccdf(BEFORE)
    assert len(findings) == 9
    assert all(f.source is Source.OPENSCAP for f in findings)
    ids = {f.rule_id for f in findings}
    assert "package_pam_pwquality_installed" in ids
    assert not any(i.startswith("xccdf_org") for i in ids)


def test_finding_fields_come_from_rule_definition() -> None:
    by_id = {f.rule_id: f for f in parse_xccdf(BEFORE)}
    f = by_id["package_pam_pwquality_installed"]
    assert f.title == "Install pam_pwquality Package"
    assert f.severity_base is Severity.MEDIUM
    assert f.band is Severity.MEDIUM
    assert "apt-get install libpam-pwquality" in f.remediation
    assert f.rationale
    assert f.evidence["profile"] == "xccdf_org.ssgproject.content_profile_cis_level1_server"
    assert f.evidence["result"] == "fail"
    assert f.first_seen is not None and f.first_seen.tzinfo is not None
    assert f.resource_type == "host.linux"


def test_unknown_severity_maps_to_info() -> None:
    by_id = {f.rule_id: f for f in parse_xccdf(BEFORE)}
    assert by_id["root_path_no_dot"].severity_base is Severity.INFO


def test_resource_id_override_and_stable_ids() -> None:
    a = parse_xccdf(AFTER, resource_id="container:oscap-target")
    b = parse_xccdf(AFTER, resource_id="container:oscap-target")
    assert {f.resource_id for f in a} == {"container:oscap-target"}
    assert [f.id for f in a] == [f.id for f in b]


def test_hardening_delta() -> None:
    before = {f.rule_id for f in parse_xccdf(BEFORE)}
    after = {f.rule_id for f in parse_xccdf(AFTER)}
    assert after < before
    assert after == {"file_permissions_ungroupowned", "root_path_all_dirs", "root_path_no_dot"}


def test_bare_test_result_root(tmp_path: Path) -> None:
    doc = tmp_path / "tr.xml"
    doc.write_text(
        '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="t" end-time="2026-01-01T00:00:00">'
        '<target>host-a</target><rule-result idref="xccdf_org.ssgproject.content_rule_x" severity="high">'
        "<result>fail</result></rule-result></TestResult>",
        encoding="utf-8",
    )
    [f] = parse_xccdf(doc)
    assert f.resource_id == "host-a"
    assert f.title == "xccdf_org.ssgproject.content_rule_x"
    assert f.severity_base is Severity.HIGH


def test_missing_test_result_raises(tmp_path: Path) -> None:
    doc = tmp_path / "empty.xml"
    doc.write_text('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"/>', encoding="utf-8")
    with pytest.raises(ValueError, match="TestResult"):
        parse_xccdf(doc)
