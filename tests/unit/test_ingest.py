"""Ingestion tests on real recorded tool output under fixtures/recorded."""

import json
import sys
import types
from collections import Counter
from pathlib import Path

import pytest

from cspm.contracts import RULE_ID_SET, Severity, Source
from cspm.ingest import ASSAY_EQUIVALENT, dedupe, ingest, match_key
from cspm.ingest.core import resource_key
from cspm.reports import build_report, validate_report
from tests.unit.test_reports_fixtures import make_finding, scan_meta

REC = Path(__file__).resolve().parents[2] / "fixtures" / "recorded"
TRIVY_CONFIG = REC / "trivy" / "config-sample-tf.json"
TRIVY_FS = REC / "trivy" / "fs-repo.json"
TRIVY_IMAGE = REC / "trivy" / "image-python312-slim.json.gz"
CHECKOV = REC / "checkov" / "sample-tf.json"


def _assay(rule: str, address: str) -> object:
    return make_finding(rule, address, resource_type="aws.s3.bucket", provider="terraform")


def test_trivy_config_recorded() -> None:
    fs = ingest(Source.TRIVY, TRIVY_CONFIG)
    assert len(fs) == 23
    assert {f.source for f in fs} == {Source.TRIVY}
    assert {f.provider for f in fs} == {"terraform"}
    sg = [f for f in fs if f.rule_id == "AWS-0107"]
    assert len(sg) == 1
    assert sg[0].evidence["lines"] == [71, 79]
    acl = next(f for f in fs if f.rule_id == "AWS-0092")
    assert acl.resource_id == "aws_s3_bucket_acl.public_data"
    assert acl.resource_type == "terraform.aws_s3_bucket_acl"
    assert acl.evidence["assay_equivalent"] == ["ASSAY-S3-001"]
    assert Counter(f.band for f in fs)[Severity.HIGH] == 12


def test_trivy_fs_recorded_has_misconfig_and_redacted_secrets() -> None:
    fs = ingest(Source.TRIVY, TRIVY_FS)
    secrets = [f for f in fs if f.resource_type == "file"]
    assert len(secrets) == 4
    assert all(f.provider == "filesystem" for f in secrets)
    assert {f.rule_id for f in secrets} == {"secret:github-pat", "secret:jwt-token", "secret:slack-access-token"}
    text = json.dumps([f.evidence for f in secrets])
    assert "Match" not in text
    assert len([f for f in fs if f.resource_type.startswith("terraform.")]) == 23


def test_trivy_image_recorded() -> None:
    fs = ingest(Source.TRIVY, TRIVY_IMAGE)
    assert len(fs) == 258
    assert {f.resource_type for f in fs} == {"package"}
    assert {f.provider for f in fs} == {"container"}
    fixable = [f for f in fs if f.evidence["fixed"]]
    assert len(fixable) == 36
    assert all(f.remediation.startswith("Upgrade ") for f in fixable)
    assert Counter(f.band for f in fs)[Severity.INFO] == 16


def test_checkov_recorded() -> None:
    fs = ingest(Source.CHECKOV, CHECKOV)
    assert len(fs) == 44
    assert {f.source for f in fs} == {Source.CHECKOV}
    assert {f.band for f in fs} == {Severity.MEDIUM}
    first = fs[0]
    assert first.evidence["file"] == "main.tf"
    assert first.resource_type.startswith("terraform.aws_")
    assert "REDACTED_USER" not in json.dumps([f.evidence for f in fs])


def test_ingested_findings_fit_report_schema() -> None:
    fs = ingest(Source.TRIVY, TRIVY_CONFIG) + ingest(Source.CHECKOV, CHECKOV)
    validate_report(build_report(scan_meta(), fs))


def test_ids_are_distinct_per_source() -> None:
    t = ingest(Source.TRIVY, TRIVY_CONFIG)
    c = ingest(Source.CHECKOV, CHECKOV)
    assert len({f.id for f in t + c}) == len(t) + len(c)


def test_resource_key_normalization() -> None:
    assert resource_key("module.net.module.sg.AWS_SECURITY_GROUP.open[0]") == "aws_security_group.open"
    assert resource_key("aws_s3_bucket_acl.public_data") == "aws_s3_bucket.public_data"
    assert resource_key("aws_s3_bucket.public_data") == "aws_s3_bucket.public_data"


def test_dedupe_against_assay_on_recorded_trivy() -> None:
    tool = ingest(Source.TRIVY, TRIVY_CONFIG)
    assay = [
        _assay("ASSAY-S3-001", "aws_s3_bucket.public_data"),
        _assay("ASSAY-S3-002", "aws_s3_bucket.public_data"),
        _assay("ASSAY-EC2-001", "aws_security_group.open_admin"),
    ]
    result = dedupe(tool, assay)
    dup_rules = sorted(f.rule_id for f, _ in result.duplicates)
    assert dup_rules == ["AWS-0086", "AWS-0087", "AWS-0091", "AWS-0092", "AWS-0093", "AWS-0094", "AWS-0107"]
    assert len(result.unique) == len(tool) - 7
    ids = {a.id for a in assay}
    assert all(hit in ids for _, hit in result.duplicates)


def test_dedupe_needs_same_resource() -> None:
    tool = ingest(Source.CHECKOV, CHECKOV)
    other = [_assay("ASSAY-S3-005", "aws_s3_bucket.somewhere_else")]
    assert dedupe(tool, other).duplicates == []
    same = [_assay("ASSAY-S3-005", "aws_s3_bucket.public_data")]
    hits = dedupe(tool, same).duplicates
    assert [f.rule_id for f, _ in hits] == ["CKV_AWS_18"]


def test_match_key_for_unmapped_tool_rule_is_empty() -> None:
    f = make_finding("CKV_AWS_999", "aws_s3_bucket.x", source=Source.CHECKOV)
    assert match_key(f) == set()
    a = make_finding("ASSAY-S3-004", "aws_s3_bucket.X")
    assert match_key(a) == {("aws_s3_bucket.x", "ASSAY-S3-004")}


def test_equivalence_table_points_at_known_rules() -> None:
    assert all(r in RULE_ID_SET for rules in ASSAY_EQUIVALENT.values() for r in rules)


def test_unknown_tool_rejected() -> None:
    with pytest.raises(ValueError, match="no parser"):
        ingest(Source.ASSAY, CHECKOV)


def test_openscap_dispatches_to_lane_h_parser(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[Path] = []

    def parse_xccdf(path: Path) -> list:
        seen.append(path)
        return [make_finding("xccdf_rule_1", "container:/home/eve/img", source=Source.OPENSCAP)]

    monkeypatch.setitem(sys.modules, "cspm.ingest.xccdf", types.SimpleNamespace(parse_xccdf=parse_xccdf))
    xml = tmp_path / "results.xml"
    fs = ingest(Source.OPENSCAP, xml)
    assert seen == [xml]
    assert fs[0].source is Source.OPENSCAP
    assert "eve" not in fs[0].resource_id


def test_openscap_without_lane_h_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "cspm.ingest.xccdf", None)
    with pytest.raises(ValueError, match=r"cspm.ingest.xccdf"):
        ingest(Source.OPENSCAP, CHECKOV)
