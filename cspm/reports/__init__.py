"""Report writers: JSON, SARIF 2.1.0, Markdown, offline HTML and a SHA-256 manifest."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cspm.reports.html_report import to_html
from cspm.reports.manifest import MANIFEST_NAME, verify_manifest, write_manifest
from cspm.reports.markdown import to_markdown
from cspm.reports.model import build_report, finding_to_dict, validate_report
from cspm.reports.redact import Redactor, redact, resource_names
from cspm.reports.sarif import to_sarif

REPORT_FILES: tuple[str, ...] = ("findings.json", "findings.sarif", "report.md", "report.html")

__all__ = [
    "MANIFEST_NAME",
    "REPORT_FILES",
    "Redactor",
    "build_report",
    "finding_to_dict",
    "redact",
    "to_html",
    "to_markdown",
    "to_sarif",
    "validate_report",
    "verify_manifest",
    "write_reports",
]


def write_reports(report: Mapping[str, Any], out_dir: Path, *, salt: str = "") -> Path:
    """Redact, validate and write every report format, then the manifest. Returns the manifest path."""
    clean: dict[str, Any] = Redactor(salt, resource_names(report.get("findings", []))).value(dict(report))
    # Finding ids are digests of the unredacted identity; keep them so the store can match them.
    for before, after in zip(report.get("findings", []), clean.get("findings", []), strict=True):
        after["id"] = before["id"]
    validate_report(clean)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = {
        "findings.json": json.dumps(clean, indent=2, ensure_ascii=False) + "\n",
        "findings.sarif": json.dumps(to_sarif(clean), indent=2, ensure_ascii=False) + "\n",
        "report.md": to_markdown(clean),
        "report.html": to_html(clean),
    }
    for name, text in contents.items():
        (out_dir / name).write_text(text, encoding="utf-8", newline="\n")
    return write_manifest(out_dir, list(contents), str(clean["scan"]["scan_id"]))
