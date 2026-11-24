"""SARIF 2.1.0 rendering of a findings report."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cspm.reports.model import sorted_findings

SARIF_VERSION = "2.1.0"
# Identifier string required by the spec; nothing is fetched from it.
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rule(f: Mapping[str, Any]) -> dict[str, Any]:
    tags = sorted({f"{c['framework']}:{c['control_id']}" for c in f["controls"]})
    rule: dict[str, Any] = {
        "id": f["rule_id"],
        "name": f["rule_id"].replace("-", ""),
        "shortDescription": {"text": f["title"]},
        "fullDescription": {"text": f["rationale"] or f["title"]},
        "help": {"text": f["remediation"] or f["title"]},
        "defaultConfiguration": {"level": _LEVEL.get(f["severity_base"], "warning")},
        "properties": {"tags": ["security", *tags], "severity_base": f["severity_base"]},
    }
    if f["references"]:
        rule["helpUri"] = f["references"][0]
    return rule


def _result(f: Mapping[str, Any], rule_index: int) -> dict[str, Any]:
    location: dict[str, Any] = {
        "logicalLocations": [
            {"name": f["resource_id"], "fullyQualifiedName": f["resource_id"], "kind": f["resource_type"]}
        ]
    }
    evidence = f.get("evidence", {})
    path = evidence.get("file") if isinstance(evidence, dict) else None
    if isinstance(path, str) and path:
        physical: dict[str, Any] = {"artifactLocation": {"uri": path.replace("\\", "/")}}
        line = evidence.get("start_line")
        if isinstance(line, int) and line > 0:
            physical["region"] = {"startLine": line}
        location["physicalLocation"] = physical
    return {
        "ruleId": f["rule_id"],
        "ruleIndex": rule_index,
        "level": _LEVEL.get(f["band"], "warning"),
        "message": {"text": f"{f['title']} ({f['resource_id']})"},
        "locations": [location],
        "partialFingerprints": {"assayFindingId/v1": f["id"]},
        "properties": {
            "security-severity": f"{float(f['score']):.1f}",
            "band": f["band"],
            "source": f["source"],
            "state": f["state"],
            "verification_status": f["verification_status"],
        },
    }


def to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    """Build a SARIF log with one run, one rule per rule_id and one result per finding."""
    findings = sorted_findings(report)
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for f in findings:
        if f["rule_id"] not in index:
            index[f["rule_id"]] = len(rules)
            rules.append(_rule(f))
    scan = report["scan"]
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "assay-cspm",
                        "version": scan["tool_version"],
                        "informationUri": "https://github.com/siiick-brain/assay-cspm",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"assay-cspm/{scan['scan_id']}"},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan["started_at"],
                        "endTimeUtc": scan["finished_at"],
                    }
                ],
                "results": [_result(f, index[f["rule_id"]]) for f in findings],
                "properties": {"mode": scan["mode"], "resource_count": scan["resource_count"]},
            }
        ],
    }
