import json
import re
from html.parser import HTMLParser
from pathlib import Path

import jsonschema
import pytest

from cspm.contracts import ControlRef, Severity
from cspm.reports import REPORT_FILES, build_report, to_html, to_markdown, to_sarif, verify_manifest, write_reports
from cspm.reports.manifest import MANIFEST_NAME
from cspm.reports.model import band_counts, load_schema, validate_report
from tests.unit.test_reports_fixtures import make_finding, scan_meta

ACCOUNT = "123456789012"


def _report() -> dict:
    findings = [
        make_finding(),
        make_finding(
            "ASSAY-EC2-001",
            f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-0abc",
            Severity.CRITICAL,
            9.6,
            resource_type="aws.ec2.security_group",
            title="SSH <open> | to the internet",
            evidence={"cidr": "0.0.0.0/0", "file": "testbed\\main.tf", "start_line": 12},
            controls=[ControlRef("cis-aws", "5.2")],
        ),
        make_finding(
            "ASSAY-IAM-004",
            f"arn:aws:iam::{ACCOUNT}:user/alice",
            Severity.MEDIUM,
            5.0,
            resource_type="aws.iam.user",
            evidence={"password": "hunter2", "note": "key AKIAIOSFODNN7EXAMPLE"},
            references=[],
        ),
    ]
    return build_report(scan_meta(), findings)


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            if name in {"src", "href", "action", "data", "poster"} and value:
                self.urls.append(value)


def test_built_report_validates() -> None:
    validate_report(_report())


def test_invalid_report_rejected() -> None:
    bad = _report()
    bad["findings"][0]["band"] = "severe"
    with pytest.raises(jsonschema.ValidationError):
        validate_report(bad)


def test_write_reports_creates_all_files_and_manifest(tmp_path: Path) -> None:
    manifest = write_reports(_report(), tmp_path / "out")
    assert manifest.name == MANIFEST_NAME
    listed = {e["path"] for e in json.loads(manifest.read_text())["files"]}
    assert listed == set(REPORT_FILES)
    assert verify_manifest(manifest) == []
    validate_report(json.loads((tmp_path / "out" / "findings.json").read_text()))


def test_written_reports_are_redacted(tmp_path: Path) -> None:
    write_reports(_report(), tmp_path)
    for name in REPORT_FILES:
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert ACCOUNT not in text, name
        assert "hunter2" not in text, name
        assert "AKIAIOSFODNN7EXAMPLE" not in text, name


def test_redaction_keeps_finding_ids(tmp_path: Path) -> None:
    report = _report()
    write_reports(report, tmp_path)
    written = json.loads((tmp_path / "findings.json").read_text())
    assert [f["id"] for f in written["findings"]] == [f["id"] for f in report["findings"]]


def test_verify_detects_tampering(tmp_path: Path) -> None:
    manifest = write_reports(_report(), tmp_path)
    (tmp_path / "report.md").write_text("changed", encoding="utf-8")
    (tmp_path / "report.html").unlink()
    problems = verify_manifest(manifest)
    assert "report.md: digest mismatch" in problems
    assert "report.html: missing" in problems


def test_verify_rejects_path_escape_and_empty(tmp_path: Path) -> None:
    (tmp_path / "m.json").write_text(json.dumps({"files": [{"path": "../x", "sha256": "0"}]}))
    assert verify_manifest(tmp_path / "m.json") == ["../x: outside report folder"]
    (tmp_path / "e.json").write_text(json.dumps({"files": []}))
    assert verify_manifest(tmp_path / "e.json") == ["manifest lists no files"]


def test_sarif_structure() -> None:
    report = _report()
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len({r["id"] for r in rules}) == len(rules) == 3
    assert len(run["results"]) == 3
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in {"error", "warning", "note", "none"}
        assert res["message"]["text"]
        assert float(res["properties"]["security-severity"]) <= 10
        assert re.fullmatch(r"[0-9a-f]{16}", res["partialFingerprints"]["assayFindingId/v1"])
    first = run["results"][0]
    assert first["level"] == "error"
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "testbed/main.tf"
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    assert "helpUri" not in rules[-1]


def test_sarif_minimal_structure_against_core_requirements() -> None:
    # Required members per SARIF 2.1.0 sections 3.13, 3.14, 3.18, 3.19 and 3.27.
    sarif = to_sarif(_report())
    assert set(sarif) >= {"version", "runs"}
    for run in sarif["runs"]:
        assert "name" in run["tool"]["driver"]
        for res in run["results"]:
            assert "message" in res
            assert "text" in res["message"]
    json.dumps(sarif)


def test_markdown_escapes_tables_and_lists_counts() -> None:
    md = to_markdown(_report())
    assert "| critical | 1 |" in md
    assert "SSH <open> \\| to the internet" in md
    assert "## Remediation" in md


def test_markdown_empty() -> None:
    md = to_markdown(build_report(scan_meta(), []))
    assert "No findings." in md


def test_html_is_offline_and_has_filters() -> None:
    html = to_html(_report())
    parser = _Links()
    parser.feed(html)
    external = [u for u in parser.urls if re.match(r"(?i)\s*(https?:)?//", u)]
    assert external == []
    assert not re.search(r"(?i)@import|url\(\s*['\"]?(https?:)?//", html)
    assert "link" not in parser.tags
    assert 'id="control"' in html and 'id="resource"' in html and 'name="band"' in html
    assert "&lt;open&gt;" in html
    assert "<open>" not in html
    assert "default-src 'none'" in html


def test_html_reference_urls_are_plain_text() -> None:
    html = to_html(_report())
    assert "https://docs.aws.amazon.com/s3/" in html
    assert 'href="https://docs.aws.amazon.com' not in html


def test_html_escapes_script_breakout() -> None:
    report = build_report(scan_meta(), [make_finding(title="</script><script>alert(1)</script>")])
    html = to_html(report)
    assert html.count("<script>") == 1


def test_html_empty_report() -> None:
    assert "No findings." in to_html(build_report(scan_meta(), []))


def test_band_counts_and_schema_loads() -> None:
    assert band_counts(_report()) == {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0}
    assert load_schema()["properties"]["schema_version"]["const"] == "1.0.0"
