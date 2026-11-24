import json
import sys
import types
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from cspm.cli import main as cli
from cspm.contracts import ControlRef, Finding, Provider, Resource, ScanContext, ScanMode, Severity, Violation
from cspm.store import ScanMeta, Store

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "cspm/contracts/findings.schema.json").read_text())
FAKE = [Resource("arn:aws:s3:::b", "aws.s3.bucket", Provider.AWS, "us-east-1", {"name": "b"})]


def _hide(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Make feature modules look missing by giving them no entry point."""
    for name in names:
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))


def _provide(monkeypatch: pytest.MonkeyPatch, name: str, **attrs: Any) -> None:
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, name, mod)


@pytest.fixture
def fake_collect(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def collect(provider: Provider, **kw: Any) -> list[Resource]:
        seen.update(kw, provider=provider)
        return FAKE

    monkeypatch.setattr(cli, "collect", collect)
    return seen


def test_scan_without_engine_writes_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_collect: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    _hide(monkeypatch, "cspm.engine")
    assert cli.main(["scan", "--out", str(tmp_path)]) == 0
    data = json.loads((tmp_path / "resources.json").read_text())
    assert data[0]["id"] == "arn:aws:s3:::b"
    assert "not available in this install" in capsys.readouterr().out
    assert fake_collect["source"] == "http://localhost:5000"
    assert fake_collect["mode"].value == "emulator"
    assert not (tmp_path / "findings.json").exists()


def test_scan_with_engine_writes_valid_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_collect: dict[str, Any]
) -> None:
    seen: dict[str, ScanContext] = {}

    def run_rules(resources: list[Resource], ctx: ScanContext) -> list[Finding]:
        seen["ctx"] = ctx
        return [
            Finding(
                rule_id="ASSAY-S3-001",
                resource_id=resources[0].id,
                resource_type=resources[0].type,
                provider="aws",
                region="us-east-1",
                title="t",
                severity_base=Severity.HIGH,
                rationale="r",
                impact="i",
                remediation="m",
                evidence={"acl": "public-read"},
                controls=[ControlRef("NIST", "AC-3")],
                first_seen=datetime(2026, 1, 1, tzinfo=UTC),
            )
        ]

    _provide(monkeypatch, "cspm.engine", run_rules=run_rules)
    rc = cli.main(
        [
            "scan",
            "--out",
            str(tmp_path),
            "--now",
            "2027-01-01T00:00:00Z",
            "--scan-id",
            "s1",
            "--endpoint",
            "http://127.0.0.1:5000",
            "--region",
            "eu-west-1",
        ]
    )
    assert rc == 0
    report = json.loads((tmp_path / "findings.json").read_text())
    jsonschema.validate(report, SCHEMA)
    assert report["scan"]["scan_id"] == "s1"
    assert report["findings"][0]["scan_id"] == "s1"
    assert report["findings"][0]["controls"] == [{"framework": "NIST", "control_id": "AC-3"}]
    assert seen["ctx"].now == datetime(2027, 1, 1, tzinfo=UTC)
    assert fake_collect["regions"] == ["eu-west-1"]


def test_scan_refuses_remote_endpoint(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["scan", "--endpoint", "https://s3.amazonaws.com", "--out", str(tmp_path)])
    assert rc == cli.EXIT_USAGE
    assert "refused" in capsys.readouterr().err
    assert not (tmp_path / "resources.json").exists()


def test_scan_live_needs_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_collect: dict[str, Any]) -> None:
    monkeypatch.delenv("CSPM_ALLOW_LIVE", raising=False)
    assert cli.main(["scan", "--live", "--out", str(tmp_path)]) == cli.EXIT_USAGE
    assert fake_collect == {}
    monkeypatch.setenv("CSPM_ALLOW_LIVE", "1")
    _hide(monkeypatch, "cspm.engine")
    assert cli.main(["scan", "--live", "--out", str(tmp_path)]) == 0
    assert fake_collect["mode"].value == "live"
    assert fake_collect["source"] is None


def test_scan_fixture_providers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_collect: dict[str, Any]) -> None:
    _hide(monkeypatch, "cspm.engine")
    assert cli.main(["scan", "--provider", "azure", "--out", str(tmp_path)]) == cli.EXIT_USAGE
    assert cli.main(["scan", "--provider", "azure", "--source", "fx", "--out", str(tmp_path)]) == 0
    assert fake_collect["mode"].value == "fixture"
    assert fake_collect["source"] == "fx"


def test_scan_real_azure_fixtures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hide(monkeypatch, "cspm.engine")
    src = ROOT / "testbed" / "azure-fixtures" / "insecure"
    assert cli.main(["scan", "--provider", "azure", "--source", str(src), "--out", str(tmp_path)]) == 0
    assert len(json.loads((tmp_path / "resources.json").read_text())) == 5


def test_collector_errors_are_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(
        ["scan", "--provider", "terraform", "--source", str(tmp_path / "missing.json"), "--out", str(tmp_path)]
    )
    assert rc == cli.EXIT_ERROR
    assert "error" in capsys.readouterr().err


def test_parse_now() -> None:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    assert cli.parse_now(None, base) == base
    assert cli.parse_now("+120d", base) == datetime(2026, 5, 1, tzinfo=UTC)
    assert cli.parse_now("2026-03-01T00:00:00", base) == datetime(2026, 3, 1, tzinfo=UTC)
    assert cli.parse_now(None).tzinfo is not None
    with pytest.raises(ValueError):
        cli.parse_now("tomorrow", base)


@pytest.mark.parametrize(
    ("argv", "module"),
    [
        (["report", "--input", "x.json"], "cspm.reports"),
        (["diff", "a", "b"], "cspm.store"),
        (["trend"], "cspm.store"),
        (["iam-review", "--policy", "p.json"], "cspm.iam"),
        (["tls-check", "localhost", "8443"], "cspm.tls"),
        (["map-coverage"], "cspm.mapping"),
    ],
)
def test_missing_feature_fails_clearly(
    argv: list[str], module: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _hide(monkeypatch, module)
    assert cli.main(argv) == cli.EXIT_UNAVAILABLE
    assert "not available in this install" in capsys.readouterr().err


def test_missing_module_fails_clearly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "cspm.reports", None)
    with pytest.raises(cli.UnavailableError, match="not available"):
        cli.require("cspm.reports", "write_reports")


def test_report_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, Any] = {}

    def write_reports(report: dict[str, Any], out: Path) -> Path:
        calls["report"], calls["out"] = report, out
        return out / "manifest.json"

    _provide(monkeypatch, "cspm.reports", write_reports=write_reports)
    src = tmp_path / "f.json"
    src.write_text('{"findings": []}')
    assert cli.main(["report", "--input", str(src), "--out", str(tmp_path / "r")]) == 0
    assert calls["report"] == {"findings": []}


def test_store_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class Store:
        def __init__(self, path: Path) -> None:
            self.path = path

        def diff(self, old: str, new: str) -> dict[str, Any]:
            return {"old": old, "new": new}

        def trend(self) -> list[int]:
            return [3, 1]

    _provide(monkeypatch, "cspm.store", Store=Store)
    assert cli.main(["diff", "--db", str(tmp_path / "x.db"), "s1", "s2"]) == 0
    assert '"new": "s2"' in capsys.readouterr().out
    assert cli.main(["trend"]) == 0

    class Bare:
        def __init__(self, path: Path) -> None:
            pass

    _provide(monkeypatch, "cspm.store", Store=Bare)
    assert cli.main(["diff", "a", "b"]) == cli.EXIT_UNAVAILABLE
    assert cli.main(["trend"]) == cli.EXIT_UNAVAILABLE


def test_iam_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _provide(monkeypatch, "cspm.iam", review=lambda policy, req: {"policy": policy, "req": req})
    pol = tmp_path / "p.json"
    pol.write_text('{"Statement": []}')
    req = tmp_path / "r.yaml"
    req.write_text("actions: [s3:GetObject]\n")
    assert cli.main(["iam-review", "--policy", str(pol), "--requirements", str(req)]) == 0
    assert "s3:GetObject" in capsys.readouterr().out
    _provide(monkeypatch, "cspm.iam", review=lambda policy, req: types.SimpleNamespace(ok=True))
    assert cli.main(["iam-review", "--policy", str(pol)]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("- 1\n")
    assert cli.main(["iam-review", "--policy", str(bad)]) == cli.EXIT_ERROR


def test_tls_check(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _provide(monkeypatch, "cspm.tls", check_endpoint=lambda h, p: [Violation({"protocol": "TLSv1.0"}, "internal")])
    assert cli.main(["tls-check", "127.0.0.1", "8443"]) == cli.EXIT_ERROR
    assert "TLSv1.0" in capsys.readouterr().out
    _provide(monkeypatch, "cspm.tls", check_endpoint=lambda h, p: [])
    assert cli.main(["tls-check", "localhost"]) == 0


def test_tls_check_remote_needs_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CSPM_ALLOW_LIVE", raising=False)
    called: list[str] = []
    _provide(monkeypatch, "cspm.tls", check_endpoint=lambda h, p: called.append(h) or [])
    assert cli.main(["tls-check", "example.com"]) == cli.EXIT_USAGE
    assert called == []


def test_map_coverage(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    refs = [ControlRef(f, "x") for f in ("cis", "nist", "iso")]
    _provide(monkeypatch, "cspm.mapping", controls_for=lambda rid: refs)
    assert cli.main(["map-coverage"]) == 0
    assert "33/33" in capsys.readouterr().out
    assert cli.main(["map-coverage", "--json", "--min-frameworks", "4"]) == cli.EXIT_ERROR
    assert len(json.loads(capsys.readouterr().out)["below_minimum"]) == 33


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "0.1.0" in capsys.readouterr().out


def test_scan_mode_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_collect: dict[str, Any]) -> None:
    _hide(monkeypatch, "cspm.engine")
    assert cli.main(["scan", "--provider", "aws", "--mode", "emulator", "--out", str(tmp_path)]) == 0
    assert fake_collect["mode"].value == "emulator"
    assert (
        cli.main(["scan", "--provider", "terraform", "--mode", "fixture", "--source", "p.json", "--out", str(tmp_path)])
        == 0
    )
    assert fake_collect["mode"].value == "fixture"
    assert cli.main(["scan", "--provider", "aws", "--mode", "fixture", "--out", str(tmp_path)]) == cli.EXIT_ERROR


def test_mode_live_alone_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_collect: dict[str, Any]
) -> None:
    monkeypatch.setenv("CSPM_ALLOW_LIVE", "1")
    assert cli.main(["scan", "--mode", "live", "--out", str(tmp_path)]) == cli.EXIT_USAGE
    assert cli.main(["scan", "--live", "--mode", "emulator", "--out", str(tmp_path)]) == cli.EXIT_USAGE
    assert fake_collect == {}
    _hide(monkeypatch, "cspm.engine")
    assert cli.main(["scan", "--live", "--mode", "live", "--out", str(tmp_path)]) == 0
    assert fake_collect["mode"].value == "live"


def test_store_commands_print_real_store_results_as_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "s.db"
    with Store(db) as store:
        store.record_scan(ScanMeta("a", ScanMode.EMULATOR, datetime(2026, 1, 1, tzinfo=UTC)), [])
        store.record_scan(ScanMeta("b", ScanMode.EMULATOR, datetime(2026, 1, 2, tzinfo=UTC)), [])
    assert cli.main(["diff", "--db", str(db), "a", "b"]) == 0
    assert json.loads(capsys.readouterr().out)["scan_b"] == "b"
    assert cli.main(["trend", "--db", str(db)]) == 0
    points = json.loads(capsys.readouterr().out)
    assert [p["scan_id"] for p in points] == ["a", "b"]
    assert points[0]["mode"] == "emulator"
    assert points[0]["finished_at"].startswith("2026-01-01")
