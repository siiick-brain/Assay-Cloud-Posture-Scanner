"""Prowler ingestion and the tool comparison, both on real recorded output."""

import json
from pathlib import Path

from cspm.contracts import Source
from cspm.ingest import dedupe, ingest
from cspm.ingest.compare import GroundTruth, overlap, score_tool, unique_detections
from tests.unit.test_reports_fixtures import make_finding

REC = Path(__file__).resolve().parents[2] / "fixtures" / "recorded"
PROWLER = REC / "prowler" / "iac-sample-tf.ocsf.json.gz"
TRUTH = GroundTruth.load(REC / "sample-ground-truth.yaml")


def _runs() -> dict:
    return {
        "trivy": ingest(Source.TRIVY, REC / "trivy" / "config-sample-tf.json"),
        "checkov": ingest(Source.CHECKOV, REC / "checkov" / "sample-tf.json"),
        "prowler": ingest(Source.PROWLER, PROWLER),
    }


def test_prowler_iac_recorded() -> None:
    fs = ingest(Source.PROWLER, PROWLER)
    assert len(fs) == 23
    assert {f.source for f in fs} == {Source.PROWLER}
    assert {f.provider for f in fs} == {"terraform"}
    sg = next(f for f in fs if f.rule_id == "AWS-0107")
    assert sg.resource_id == "aws_security_group.open_admin"
    assert sg.evidence["file"] == "main.tf"
    assert all(f.references for f in fs)


def test_prowler_wraps_same_checks_as_trivy() -> None:
    runs = _runs()
    key = lambda fs: sorted((f.rule_id, f.resource_id) for f in fs)  # noqa: E731
    assert key(runs["prowler"]) == key(runs["trivy"])


def test_prowler_native_and_ocsf_shapes(tmp_path: Path) -> None:
    native = [
        {
            "CheckID": "s3_bucket_public_access",
            "Status": "FAIL",
            "Severity": "critical",
            "ResourceArn": "arn:aws:s3:::open-bucket",
            "ResourceType": "AwsS3Bucket",
            "Provider": "aws",
            "Region": "us-east-1",
            "CheckTitle": "Bucket is public",
            "StatusExtended": "Bucket open-bucket is public",
            "Remediation": {"Recommendation": {"Text": "Block it", "Url": "https://example.invalid/fix"}},
        },
        {"CheckID": "x", "Status": "PASS"},
        "not a finding",
    ]
    p = tmp_path / "native.json"
    p.write_text(json.dumps(native))
    fs = ingest(Source.PROWLER, p)
    assert len(fs) == 1
    assert fs[0].resource_id.startswith("arn:aws:s3:::REDACTED_NAME_")
    assert fs[0].references == ["https://example.invalid/fix"]
    ocsf = {
        "finding_info": {"title": "Open", "uid": "u1"},
        "status_code": "FAIL",
        "severity": "High",
        "resources": [{"uid": "res-1", "type": "Pod", "region": "eu"}],
        "cloud": {"provider": "kubernetes"},
    }
    lines = tmp_path / "o.jsonl"
    lines.write_text(json.dumps(ocsf) + "\n" + json.dumps(ocsf | {"status_code": "PASS"}) + "\n")
    got = ingest(Source.PROWLER, lines)
    assert [(f.rule_id, f.resource_id, f.provider, f.region) for f in got] == [("u1", "res-1", "kubernetes", "eu")]


def test_checkov_list_output(tmp_path: Path) -> None:
    report = {
        "check_type": "kubernetes",
        "results": {"failed_checks": [{"check_id": "CKV_K8S_1", "resource": "Pod.default.x", "severity": "LOW"}]},
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps([report, {"check_type": "secrets", "results": {}}]))
    fs = ingest(Source.CHECKOV, p)
    assert [(f.rule_id, f.provider, f.resource_type, f.band.value) for f in fs] == [
        ("CKV_K8S_1", "kubernetes", "iac.kubernetes", "low")
    ]


def test_comparison_numbers_match_doc() -> None:
    scores = {t: score_tool(t, fs, TRUTH) for t, fs in _runs().items()}
    assert len(TRUTH.issues) == 14
    assert {
        t: (s.findings, len(s.detected), len(s.false_positives), len(s.beyond_seed)) for t, s in scores.items()
    } == {
        "trivy": (23, 12, 0, 8),
        "checkov": (44, 14, 4, 21),
        "prowler": (23, 12, 0, 8),
    }
    assert scores["trivy"].missed == {
        ("aws_iam_policy.star", "ASSAY-IAM-001"),
        ("aws_s3_bucket.public_data", "ASSAY-S3-003"),
    }
    unique = unique_detections(list(scores.values()))
    assert unique["checkov"] == scores["trivy"].missed
    assert unique["trivy"] == frozenset()
    assert sum(len(v) == 3 for v in overlap(scores.values()).values()) == 12


def test_dedupe_trivy_against_checkov_mapped_issues() -> None:
    runs = _runs()
    stand_in = [make_finding(rule, address, provider="terraform") for address, rule in sorted(TRUTH.issues)]
    result = dedupe(runs["trivy"], stand_in)
    assert len(result.duplicates) == 15
    assert len(result.unique) == 8
