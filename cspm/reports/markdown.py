"""Markdown rendering of a findings report."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cspm.reports.model import SEVERITY_ORDER, band_counts, sorted_findings


def _cell(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'")


def to_markdown(report: Mapping[str, Any]) -> str:
    """Summary, counts per band and one table row per finding, then remediation per finding."""
    scan = report["scan"]
    counts = band_counts(report)
    findings = sorted_findings(report)
    lines = [
        "# assay-cspm findings report",
        "",
        f"- Scan: {_cell(scan['scan_id'])}",
        f"- Mode: {scan['mode']}",
        f"- Providers: {', '.join(scan['providers']) or 'none'}",
        f"- Started: {scan['started_at']}",
        f"- Finished: {scan['finished_at']}",
        f"- Resources: {scan['resource_count']}",
        f"- Tool version: {_cell(scan['tool_version'])}",
        f"- Findings: {len(findings)}",
        "",
        "| Band | Count |",
        "|---|---|",
        *[f"| {band} | {counts[band]} |" for band in SEVERITY_ORDER],
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines += [
        "| Band | Score | Rule | Resource | Title | Controls | State | Verification |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for f in findings:
        controls = ", ".join(f"{c['framework']} {c['control_id']}" for c in f["controls"])
        lines.append(
            f"| {f['band']} | {float(f['score']):.1f} | {_cell(f['rule_id'])} | {_cell(f['resource_id'])} "
            f"| {_cell(f['title'])} | {_cell(controls)} | {f['state']} | {f['verification_status']} |"
        )
    lines += ["", "## Remediation", ""]
    for f in findings:
        lines += [
            f"### {_cell(f['rule_id'])} on {_cell(f['resource_id'])}",
            "",
            f"- Why: {_cell(f['rationale'])}",
            f"- Impact: {_cell(f['impact'])}",
            f"- Fix: {_cell(f['remediation'])}",
            "",
        ]
    return "\n".join(lines)
