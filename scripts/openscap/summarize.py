"""Trim OpenSCAP results for commit and write a before and after summary.

The full results files are about 9 MB because they embed the whole benchmark.
The trimmed copy keeps the TestResult untouched plus the Rule definitions of
failed rules, which is all cspm.ingest.xccdf needs. Nothing in the results
identifies the host (target is "unknown", identifier is chroot:///target).

Usage: python scripts/openscap/summarize.py [artifacts/openscap] [fixtures/recorded/openscap]
"""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

X = "http://checklists.nist.gov/xccdf/1.2"
NS = {"x": X}
PREFIX = "xccdf_org.ssgproject.content_rule_"


def trim(src: Path, dst: Path) -> dict[str, str]:
    ET.register_namespace("", X)
    root = ET.parse(src).getroot()  # noqa: S314
    result = root.find(".//x:TestResult", NS)
    if result is None:
        raise SystemExit(f"{src} has no TestResult")
    outcomes = {rr.get("idref", ""): rr.findtext("x:result", "", NS) for rr in result.iter(f"{{{X}}}rule-result")}
    keep = {k for k, v in outcomes.items() if v == "fail"}
    bench = ET.Element(f"{{{X}}}Benchmark", {"id": root.get("id", "trimmed"), "resolved": "1"})
    ET.SubElement(bench, f"{{{X}}}status").text = "draft"
    ET.SubElement(bench, f"{{{X}}}version").text = result.get("version", "")
    for rule in root.iter(f"{{{X}}}Rule"):
        if rule.get("id") in keep:
            bench.append(rule)
    bench.append(result)
    dst.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(bench).write(dst, encoding="utf-8", xml_declaration=True)
    return outcomes


def main(argv: list[str]) -> int:
    src = Path(argv[1] if len(argv) > 1 else "artifacts/openscap")
    dst = Path(argv[2] if len(argv) > 2 else "fixtures/recorded/openscap")
    runs = {label: trim(src / f"{label}-results.xml", dst / f"{label}-results.xml") for label in ("before", "after")}
    before, after = runs["before"], runs["after"]
    summary = {
        "profile": "xccdf_org.ssgproject.content_profile_cis_level1_server",
        "datastream": "ssg-ubuntu2404-ds.xml from scap-security-guide 0.1.82",
        "scanner": "OpenSCAP 1.3.9 (Ubuntu 1.3.9+dfsg-1.1ubuntu2)",
        "counts": {label: dict(sorted(Counter(r.values()).items())) for label, r in runs.items()},
        "fixed": sorted(k.removeprefix(PREFIX) for k in before if before[k] == "fail" and after.get(k) == "pass"),
        "still_failing": sorted(k.removeprefix(PREFIX) for k in after if after[k] == "fail"),
        "regressed": sorted(k.removeprefix(PREFIX) for k in after if after[k] == "fail" and before.get(k) != "fail"),
    }
    (dst / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary["counts"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
