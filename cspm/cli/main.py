"""cspm command line. Feature modules load lazily so a missing one fails with a clear message."""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import json
import re
import sys
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from cspm import __version__
from cspm.collectors import collect
from cspm.collectors.guard import (
    EMULATOR_HOSTS,
    EndpointRefusedError,
    LiveModeRefusedError,
    check_emulator_endpoint,
    check_live_allowed,
)
from cspm.contracts import (
    RULE_IDS,
    SCHEMA_VERSION,
    Finding,
    Provider,
    ScanContext,
    ScanMode,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3
OFFSET = re.compile(r"^\+(\d+)d$")


class UnavailableError(RuntimeError):
    """A command needs a module that is missing from this install."""


def require(module: str, attr: str) -> Any:
    """Import `module.attr` or raise UnavailableError naming what is missing."""
    try:
        mod = importlib.import_module(module)
    except ImportError as exc:
        raise UnavailableError(f"{module} is not available in this install") from exc
    fn = getattr(mod, attr, None)
    if fn is None:
        raise UnavailableError(f"{module}.{attr} is not available in this install")
    return fn


def parse_now(value: str | None, base: datetime | None = None) -> datetime:
    """Accept an ISO 8601 time or an offset such as +120d from the current time."""
    start = base or datetime.now(UTC)
    if not value:
        return start
    match = OFFSET.match(value)
    if match:
        return start + timedelta(days=int(match.group(1)))
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def iso_z(value: datetime | None) -> str | None:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def finding_to_dict(f: Finding) -> dict[str, Any]:
    """Serialize a Finding in the findings.schema.json shape."""
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "source": f.source.value,
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "provider": f.provider,
        "region": f.region,
        "title": f.title,
        "severity_base": f.severity_base.value,
        "score": f.score,
        "band": f.band.value,
        "rationale": f.rationale,
        "impact": f.impact,
        "remediation": f.remediation,
        "evidence": f.evidence,
        "controls": [{"framework": c.framework, "control_id": c.control_id} for c in f.controls],
        "references": list(f.references),
        "state": f.state.value,
        "verification_status": f.verification_status.value,
        "owner": f.owner,
        "first_seen": iso_z(f.first_seen),
        "last_seen": iso_z(f.last_seen),
        "due_date": iso_z(f.due_date),
        "scan_id": f.scan_id,
    }


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _scan_mode(args: argparse.Namespace) -> ScanMode:
    if args.live or args.mode == ScanMode.LIVE.value:
        # Either spelling asks for live, but both switches plus the env var are still required.
        if not (args.live and args.mode in {None, ScanMode.LIVE.value}):
            raise LiveModeRefusedError("live mode needs --live (with --mode live or no --mode) and CSPM_ALLOW_LIVE=1")
        check_live_allowed(args.live)
        return ScanMode.LIVE
    default = ScanMode.FIXTURE if args.provider in {"azure", "terraform"} else ScanMode.EMULATOR
    mode = ScanMode(args.mode) if args.mode else default
    if mode is not default:
        raise ValueError(f"--provider {args.provider} supports --mode {default.value} or live")
    return mode


def cmd_scan(args: argparse.Namespace) -> int:
    mode = _scan_mode(args)
    provider = Provider(args.provider)
    source = args.endpoint if provider is Provider.AWS else args.source
    if provider is Provider.AWS and mode is ScanMode.EMULATOR:
        source = check_emulator_endpoint(source or "http://localhost:5000")
    if provider is not Provider.AWS and mode is not ScanMode.LIVE and not source:
        print(f"scan --provider {args.provider} needs --source", file=sys.stderr)
        return EXIT_USAGE
    started = datetime.now(UTC)
    now = parse_now(args.now, started)
    resources = collect(provider, mode=mode, source=source, regions=args.region or None)
    out = Path(args.out)
    _write_json(out / "resources.json", [r.to_dict() for r in resources])
    print(f"collected {len(resources)} resources -> {out / 'resources.json'}")
    try:
        run_rules = require("cspm.engine", "run_rules")
    except UnavailableError as exc:
        print(f"{exc}; wrote resources only")
        return EXIT_OK
    scan_id = args.scan_id or uuid.uuid4().hex[:12]
    findings: list[Finding] = run_rules(resources, ScanContext(now=now, mode=mode, inventory=tuple(resources)))
    for f in findings:
        f.scan_id = scan_id
    report = {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "scan_id": scan_id,
            "started_at": iso_z(started),
            "finished_at": iso_z(datetime.now(UTC)),
            "mode": mode.value,
            "providers": [provider.value],
            "resource_count": len(resources),
            "tool_version": __version__,
        },
        "findings": [finding_to_dict(f) for f in findings],
    }
    _write_json(out / "findings.json", report)
    print(f"{len(findings)} findings -> {out / 'findings.json'}")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    write_reports = require("cspm.reports", "write_reports")
    report = json.loads(Path(args.input).read_text(encoding="utf-8"))
    manifest = write_reports(report, Path(args.out))
    print(f"reports written, manifest {manifest}")
    return EXIT_OK


def _store(args: argparse.Namespace) -> Any:
    return require("cspm.store", "Store")(Path(args.db))


def _plain(value: Any) -> Any:
    # Store results are slotted dataclasses, which str() would print as a repr.
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: getattr(value, f.name) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def cmd_diff(args: argparse.Namespace) -> int:
    store = _store(args)
    method = getattr(store, "diff", None)
    if method is None:
        raise UnavailableError("cspm.store.Store.diff is not available in this install")
    print(json.dumps(method(args.old, args.new), indent=2, default=_plain))
    return EXIT_OK


def cmd_trend(args: argparse.Namespace) -> int:
    store = _store(args)
    method = getattr(store, "trend", None)
    if method is None:
        raise UnavailableError("cspm.store.Store.trend is not available in this install")
    print(json.dumps(method(), indent=2, default=_plain))
    return EXIT_OK


def _load_doc(path: str) -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) if path.endswith((".yaml", ".yml")) else json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must hold a JSON or YAML object")
    return data


def cmd_iam_review(args: argparse.Namespace) -> int:
    review = require("cspm.iam", "review")
    requirements = _load_doc(args.requirements) if args.requirements else {}
    result = review(_load_doc(args.policy), requirements)
    print(
        json.dumps(
            result if isinstance(result, dict) else getattr(result, "__dict__", str(result)), indent=2, default=str
        )
    )
    return EXIT_OK


def cmd_tls_check(args: argparse.Namespace) -> int:
    # TLS checks open a socket, so anything off this machine needs the live switches too.
    if args.host.lower() not in EMULATOR_HOSTS:
        check_live_allowed(args.live)
    check_endpoint = require("cspm.tls", "check_endpoint")
    violations = check_endpoint(args.host, args.port)
    for v in violations:
        print(json.dumps({"exposure": v.exposure, "evidence": dict(v.evidence)}, default=str))
    print(f"{len(violations)} TLS issues on {args.host}:{args.port}")
    return EXIT_OK if not violations else EXIT_ERROR


def cmd_map_coverage(args: argparse.Namespace) -> int:
    controls_for = require("cspm.mapping", "controls_for")
    rows: list[dict[str, Any]] = []
    for rule in RULE_IDS:
        refs = controls_for(rule.id)
        frameworks = sorted({r.framework for r in refs})
        rows.append({"rule_id": rule.id, "frameworks": frameworks, "framework_count": len(frameworks)})
    short = [r["rule_id"] for r in rows if r["framework_count"] < args.min_frameworks]
    if args.json:
        print(json.dumps({"rules": rows, "below_minimum": short}, indent=2))
    else:
        for r in rows:
            print(f"{r['rule_id']:<18} {r['framework_count']}  {', '.join(r['frameworks'])}")
        print(f"{len(rows) - len(short)}/{len(rows)} rules map to at least {args.min_frameworks} frameworks")
    return EXIT_OK if not short else EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cspm", description="Cloud security posture scanner (assay-cspm).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="collect resources and run rules")
    scan.add_argument("--provider", choices=[p.value for p in Provider], default="aws")
    scan.add_argument("--mode", choices=[m.value for m in ScanMode], help="default: emulator for aws, else fixture")
    scan.add_argument("--endpoint", help="emulator URL for AWS (default http://localhost:5000)")
    scan.add_argument("--source", help="fixture file or folder (azure) or plan JSON (terraform)")
    scan.add_argument("--region", action="append", help="AWS region, repeatable (default us-east-1)")
    scan.add_argument("--now", help="scan clock: ISO 8601 time or +Nd offset (default: current time)")
    scan.add_argument("--out", default="out", help="output folder")
    scan.add_argument("--scan-id", help="fixed scan ID, handy for reproducible runs")
    scan.add_argument("--live", action="store_true", help="scan real AWS; also needs CSPM_ALLOW_LIVE=1")
    scan.set_defaults(func=cmd_scan)

    report = sub.add_parser("report", help="render reports from a findings JSON file")
    report.add_argument("--input", required=True)
    report.add_argument("--out", default="reports")
    report.set_defaults(func=cmd_report)

    diff = sub.add_parser("diff", help="compare two recorded scans")
    diff.add_argument("--db", default="cspm.db")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.set_defaults(func=cmd_diff)

    trend = sub.add_parser("trend", help="finding counts over recorded scans")
    trend.add_argument("--db", default="cspm.db")
    trend.set_defaults(func=cmd_trend)

    iam = sub.add_parser("iam-review", help="least-privilege review of an IAM policy document")
    iam.add_argument("--policy", required=True)
    iam.add_argument("--requirements")
    iam.set_defaults(func=cmd_iam_review)

    tls = sub.add_parser("tls-check", help="TLS and certificate checks on one endpoint")
    tls.add_argument("host")
    tls.add_argument("port", type=int, nargs="?", default=443)
    tls.add_argument("--live", action="store_true", help="allow a host that is not local")
    tls.set_defaults(func=cmd_tls_check)

    cov = sub.add_parser("map-coverage", help="framework coverage per rule")
    cov.add_argument("--min-frameworks", type=int, default=3)
    cov.add_argument("--json", action="store_true")
    cov.set_defaults(func=cmd_map_coverage)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the `cspm` console script."""
    args = build_parser().parse_args(argv)
    func: Callable[[argparse.Namespace], int] = args.func
    try:
        return func(args)
    except UnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    except (EndpointRefusedError, LiveModeRefusedError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_parser", "main"]
