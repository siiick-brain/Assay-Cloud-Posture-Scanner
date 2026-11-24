"""Synthetic finding sets only. The recorded Moto run is in docs/demo/remediation-demo.md."""

import json
from pathlib import Path

from cspm.contracts import Severity
from cspm.reports import build_report
from cspm.store import Store
from cspm.store.demo import main, run_demo
from tests.unit.test_reports_fixtures import make_finding, scan_meta

S3 = make_finding()
SG = make_finding("ASSAY-EC2-001", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1", Severity.CRITICAL, 9.6)
KMS = make_finding("ASSAY-KMS-001", "arn:aws:kms:us-east-1:123456789012:key/k1", Severity.MEDIUM, 4.8)


def _reports() -> list[dict]:
    sets = [[S3, SG, KMS], [SG, KMS], [KMS], [KMS, S3]]
    out = []
    for i, findings in enumerate(sets):
        scan = scan_meta(f"demo-{i}") | {"finished_at": f"2026-11-0{i + 1}T12:00:00+00:00"}
        out.append(build_report(scan, findings))
    return out


def test_demo_shows_closures_and_one_regression() -> None:
    with Store(":memory:") as store:
        lines = run_demo(_reports(), store, claim_absent=True)
        text = "\n".join(lines)
        assert text.count("  closed   ") == 2
        assert text.count("  reopened ") == 1
        assert "[verified]" in text
        assert "  claim  ASSAY-S3-001" in text
        assert "  demo-3 | 2 | 0 | 0 | 1 | 2" in text
        assert "123456789012" not in text


def test_demo_without_claims_still_closes() -> None:
    with Store(":memory:") as store:
        lines = run_demo(_reports(), store)
    assert not any("claim" in line for line in lines)
    assert sum("closed" in line for line in lines if line.startswith("  closed")) == 2


def test_demo_cli(tmp_path: Path) -> None:
    paths = []
    for i, report in enumerate(_reports()):
        p = tmp_path / f"s{i}.json"
        p.write_text(json.dumps(report))
        paths.append(str(p))
    db = tmp_path / "d" / "r.db"
    seen: list[str] = []
    assert main(["--db", str(db), "--claim-absent", *paths], out=seen.append) == 0
    assert any("reopened" in s for s in seen)
    assert main(["--db", str(db), *paths], out=seen.append) == 2
