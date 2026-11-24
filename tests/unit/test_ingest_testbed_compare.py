"""Tool comparison on the testbed, recomputed from the recorded real runs (docs/tool-comparison.md)."""

from collections import Counter
from pathlib import Path

import yaml

from cspm.contracts import Finding, ScanContext, ScanMode, Severity, Source
from cspm.engine import run_rules
from cspm.ingest import ingest
from cspm.ingest.compare import GroundTruth, ToolScore, overlap, score_tool, unique_detections
from tests.integration.test_recall import GROUND_TRUTH, SCAN_TIME, load_ground_truth, load_resources, missed

ROOT = Path(__file__).resolve().parents[2]
REC = ROOT / "fixtures" / "recorded"
TF_TRUTH_PATH = REC / "testbed-ground-truth-tf.yaml"
TF_TRUTH = GroundTruth.load(TF_TRUTH_PATH)
RUNS = {
    "trivy": (Source.TRIVY, "trivy/testbed-{}.json"),
    "checkov": (Source.CHECKOV, "checkov/testbed-{}.json"),
    "prowler": (Source.PROWLER, "prowler/testbed-{}.json.gz"),
}
# Seeded issues with no Terraform resource or with runtime-only evidence. No IaC scanner can see them.
RUNTIME_ONLY = {"ASSAY-EC2-006", "ASSAY-IAM-004", "ASSAY-IAM-005", "ASSAY-IAM-008", "ASSAY-LOG-001"}


def _tool(name: str, stack: str) -> list[Finding]:
    source, pattern = RUNS[name]
    return ingest(source, REC / pattern.format(stack))


def _tf_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = yaml.safe_load(TF_TRUTH_PATH.read_text(encoding="utf-8"))["issues"]
    return rows


def _assay_score() -> ToolScore:
    """Assay scans collector output with ARNs, so its hits are mapped back to Terraform keys by name."""
    truth = [r for r in load_ground_truth(GROUND_TRUTH) if r["provider"] == "aws"]
    resources = load_resources([ROOT / "testbed" / "recorded" / "insecure-aws.json"])
    findings = run_rules(resources, ScanContext(now=SCAN_TIME, mode=ScanMode.EMULATOR))
    gaps = set(missed(truth, findings, resources))
    detected = frozenset(
        (r["resource"], r["rule"])
        for r in _tf_rows()
        if not any(g.startswith(f"{r['rule']} on ") and g.endswith(f" {r['name']}") for g in gaps)
    )
    extra = len(findings) - len(detected)
    return ToolScore("assay", len(findings), detected, TF_TRUTH.issues - detected, (), tuple(findings[:extra]))


def test_tf_ground_truth_matches_testbed_ground_truth() -> None:
    aws = {(r["rule_id"], str(r["resource_name"])) for r in load_ground_truth(GROUND_TRUTH) if r["provider"] == "aws"}
    assert {(r["rule"], r["name"]) for r in _tf_rows()} == aws
    assert len(TF_TRUTH.issues) == 16


def test_testbed_comparison_numbers_match_doc() -> None:
    scores = {t: score_tool(t, _tool(t, "insecure"), TF_TRUTH) for t in RUNS}
    secure = {t: len(_tool(t, "secure")) for t in RUNS}
    assert {
        t: (s.findings, len(s.detected), len(s.false_positives), len(s.beyond_seed), secure[t])
        for t, s in scores.items()
    } == {
        "trivy": (17, 9, 0, 5, 5),
        "checkov": (39, 9, 4, 21, 19),
        "prowler": (17, 9, 0, 5, 5),
    }
    missed_rules = {t: sorted(r for _, r in s.missed) for t, s in scores.items()}
    assert missed_rules["trivy"] == sorted(RUNTIME_ONLY | {"ASSAY-IAM-001", "ASSAY-S3-003"})
    assert missed_rules["checkov"] == sorted(RUNTIME_ONLY | {"ASSAY-EC2-003", "ASSAY-IAM-002"})
    assert missed_rules["prowler"] == missed_rules["trivy"]
    assert unique_detections(list(scores.values()))["checkov"] == {
        ("aws_s3_bucket.unencrypted", "ASSAY-S3-003"),
        ("aws_iam_policy.admin_wildcard", "ASSAY-IAM-001"),
    }
    assert Counter(len(v) for v in overlap(scores.values()).values()) == {3: 7, 2: 2, 1: 2}


def test_assay_finds_every_seeded_issue_and_nothing_else() -> None:
    assay = _assay_score()
    assert (assay.findings, len(assay.detected), len(assay.beyond_seed)) == (16, 16, 0)
    secure = load_resources([ROOT / "testbed" / "recorded" / "secure-aws.json"])
    assert run_rules(secure, ScanContext(now=SCAN_TIME, mode=ScanMode.EMULATOR)) == []
    tools = [score_tool(t, _tool(t, "insecure"), TF_TRUTH) for t in RUNS]
    only_assay = unique_detections([*tools, assay])["assay"]
    assert {r for _, r in only_assay} == RUNTIME_ONLY


def test_recorded_testbed_runs_ingest_as_terraform() -> None:
    for t in RUNS:
        for stack in ("insecure", "secure"):
            fs = _tool(t, stack)
            assert fs
            assert {f.provider for f in fs} == {"terraform"}
            assert all(f.resource_type.startswith("terraform.aws_") for f in fs)
    sg = next(f for f in _tool("trivy", "insecure") if f.rule_id == "AWS-0107")
    assert sg.evidence["assay_equivalent"] == ["ASSAY-EC2-001", "ASSAY-EC2-002", "ASSAY-EC2-003"]
    assert sg.resource_id == "aws_security_group.open"


def test_scanner_image_scan_recorded() -> None:
    path = REC / "trivy" / "image-assay-cspm.json"
    fs = ingest(Source.TRIVY, path)
    assert len(fs) == 258
    assert {f.provider for f in fs} == {"container"}
    assert Counter(f.band for f in fs) == {
        Severity.HIGH: 54,
        Severity.MEDIUM: 106,
        Severity.LOW: 82,
        Severity.INFO: 16,
    }
    assert len([f for f in fs if f.evidence["fixed"]]) == 36
    pip = [f for f in fs if f.evidence["package"] == "pip"]
    assert len(pip) == 6
    summary = yaml.safe_load(path.read_text(encoding="utf-8"))["TrimmedBy"]
    assert summary["total"] == 258


def test_trivy_fs_recorded_on_integration_branch() -> None:
    fs = ingest(Source.TRIVY, REC / "trivy" / "fs-repo-integration.json")
    docker = [f for f in fs if f.resource_type == "iac.dockerfile"]
    assert sorted((f.evidence["file"], f.rule_id) for f in docker) == [
        ("Dockerfile", "DS-0026"),
        ("docker/openscap/Dockerfile", "DS-0002"),
        ("docker/openscap/Dockerfile", "DS-0026"),
        ("docker/target/Dockerfile", "DS-0002"),
        ("docker/target/Dockerfile", "DS-0026"),
    ]
    assert not [f for f in fs if f.resource_type in ("package", "file")]
