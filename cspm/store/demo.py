"""Fix-and-rescan demo: record a sequence of findings reports and narrate the lifecycle changes."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from cspm.contracts import FindingState
from cspm.reports.model import finding_from_dict, validate_report
from cspm.store.store import ACTIVE_STATES, ScanMeta, Store


def _label(store: Store, fid: str) -> str:
    f = store.get(fid)
    return f"{f.rule_id} {f.resource_id}" if f else fid


def run_demo(reports: Sequence[Mapping[str, Any]], store: Store, *, claim_absent: bool = False) -> list[str]:
    """Record each report in order and return one line per lifecycle event plus a trend table.

    With claim_absent, findings missing from the next report are first marked fixed_claimed,
    which mirrors an operator claiming the fix they just applied before rescanning.
    """
    lines: list[str] = []
    for step, report in enumerate(reports):
        validate_report(report)
        findings = [finding_from_dict(f) for f in report["findings"]]
        if claim_absent and step > 0:
            seen = {f.id for f in findings}
            for stored in store.findings(ACTIVE_STATES - {FindingState.FIXED_CLAIMED}):
                if stored.id not in seen:
                    store.claim_fixed(stored.id, at=ScanMeta.from_dict(report["scan"]).finished_at, note="demo step")
                    lines.append(f"  claim  {_label(store, stored.id)}")
        diff = store.record_scan(ScanMeta.from_dict(report["scan"]), findings)
        lines.append(f"step {step}: scan {diff.scan_id} ({diff.mode.value}) {json.dumps(diff.counts)}")
        for fid in diff.new:
            lines.append(f"  new      {_label(store, fid)}")
        for fid in diff.closed:
            got = store.get(fid)
            status = got.verification_status.value if got else "?"
            lines.append(f"  closed   {_label(store, fid)} [{status}]")
        for fid in diff.reopened:
            lines.append(f"  reopened {_label(store, fid)}")
    lines.append("trend: scan | observed | new | closed | reopened | active")
    for p in store.trend():
        lines.append(f"  {p.scan_id} | {p.observed} | {p.new} | {p.closed} | {p.reopened} | {p.active_after}")
    return lines


def main(argv: Sequence[str] | None = None, out: Callable[[str], object] = print) -> int:
    parser = argparse.ArgumentParser(description="Record findings reports in order and show closures and regressions.")
    parser.add_argument("reports", nargs="+", type=Path, help="findings.json files in scan order")
    parser.add_argument("--db", type=Path, default=Path("artifacts/demo/remediation.db"))
    parser.add_argument("--claim-absent", action="store_true", help="claim fixes for findings gone in the next scan")
    args = parser.parse_args(argv)
    if args.db.exists():
        out(f"refusing to reuse existing store {args.db}")
        return 2
    args.db.parent.mkdir(parents=True, exist_ok=True)
    reports = [json.loads(p.read_text(encoding="utf-8")) for p in args.reports]
    with Store(args.db) as store:
        for line in run_demo(reports, store, claim_absent=args.claim_absent):
            out(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
