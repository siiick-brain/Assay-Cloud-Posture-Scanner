"""Turn OpenSCAP XCCDF 1.2 result files into findings with source=openscap."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from cspm.contracts.finding import Finding, Severity, Source

NS = {"x": "http://checklists.nist.gov/xccdf/1.2"}
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
RESOURCE_TYPE = "host.linux"
FAIL_RESULTS = frozenset({"fail"})
_SEVERITY = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
_TEXT_LIMIT = 600


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


def _clip(text: str) -> str:
    return text if len(text) <= _TEXT_LIMIT else text[: _TEXT_LIMIT - 3].rstrip() + "..."


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _load(path: Path) -> tuple[ET.Element, ET.Element]:
    # The input is a file our own scanner container wrote. ElementTree does not
    # resolve external entities and Python's expat caps entity expansion.
    root = ET.parse(path).getroot()  # noqa: S314
    result = root if root.tag.endswith("TestResult") else root.find(".//x:TestResult", NS)
    if result is None:
        raise ValueError(f"{path} has no XCCDF 1.2 TestResult element")
    return root, result


def count_results(path: Path) -> Counter[str]:
    """Count rule results (pass, fail, notapplicable, notselected and so on) in a results file."""
    _, result = _load(path)
    rule_results = result.iter(f"{{{NS['x']}}}rule-result")
    return Counter(rr.findtext("x:result", default="unknown", namespaces=NS) for rr in rule_results)


def parse_xccdf(path: Path, *, resource_id: str | None = None) -> list[Finding]:
    """Return one finding per failed rule in an XCCDF results file.

    resource_id defaults to the scan target named in the results.
    """
    root, result = _load(Path(path))
    rules = {r.get("id", ""): r for r in root.iter(f"{{{NS['x']}}}Rule")}
    profile_el = result.find("x:profile", NS)
    profile = profile_el.get("idref", "") if profile_el is not None else ""
    target = resource_id or result.findtext("x:target", namespaces=NS) or "unknown-host"
    seen = _parse_time(result.get("end-time"))
    benchmark = result.find("x:benchmark", NS)

    findings: list[Finding] = []
    for rr in result.iter(f"{{{NS['x']}}}rule-result"):
        outcome = rr.findtext("x:result", default="", namespaces=NS)
        if outcome not in FAIL_RESULTS:
            continue
        xccdf_id = rr.get("idref", "")
        rule = rules.get(xccdf_id)
        severity = _SEVERITY.get(rr.get("severity", ""), Severity.INFO)
        hrefs = {ref.get("href", "") for ref in rule.findall("x:reference", NS)} if rule is not None else set()
        refs = sorted(hrefs - {""})
        idents = [_text(i) for i in rr.findall("x:ident", NS)]
        title = _text(rule.find("x:title", NS)) if rule is not None else xccdf_id
        findings.append(
            Finding(
                rule_id=xccdf_id.removeprefix(RULE_PREFIX),
                resource_id=target,
                resource_type=RESOURCE_TYPE,
                provider="container",
                region="local",
                title=title,
                severity_base=severity,
                band=severity,
                rationale=_clip(_text(rule.find("x:rationale", NS)) if rule is not None else ""),
                impact="The host setting departs from the CIS-aligned SSG profile it was scanned against.",
                remediation=_clip(_text(rule.find("x:description", NS)) if rule is not None else ""),
                evidence={
                    "xccdf_rule": xccdf_id,
                    "result": outcome,
                    "profile": profile,
                    "benchmark": benchmark.get("href", "") if benchmark is not None else "",
                    "idents": idents,
                },
                source=Source.OPENSCAP,
                references=refs,
                first_seen=seen,
                last_seen=seen,
            )
        )
    return findings
