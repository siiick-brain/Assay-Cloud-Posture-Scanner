"""Parsers for third-party scanner JSON and deduplication against assay findings."""

from __future__ import annotations

import gzip
import importlib
import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cspm.contracts import Finding, Severity, Source
from cspm.reports.redact import Redactor

# Nominal scores so imported findings sort next to assay findings of the same band.
BAND_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "unknown": Severity.INFO,
}

# Tool check id -> assay rule ids that describe the same issue. Used only for dedupe.
ASSAY_EQUIVALENT: dict[str, tuple[str, ...]] = {
    # Trivy (AVD ids are normalized to the short AWS-NNNN form).
    "AWS-0092": ("ASSAY-S3-001",),
    "AWS-0086": ("ASSAY-S3-002",),
    "AWS-0087": ("ASSAY-S3-002",),
    "AWS-0091": ("ASSAY-S3-002",),
    "AWS-0093": ("ASSAY-S3-002",),
    "AWS-0094": ("ASSAY-S3-002",),
    "AWS-0088": ("ASSAY-S3-003",),
    "AWS-0090": ("ASSAY-S3-004",),
    "AWS-0089": ("ASSAY-S3-005",),
    "AWS-0107": ("ASSAY-EC2-001", "ASSAY-EC2-002", "ASSAY-EC2-003"),
    "AWS-0026": ("ASSAY-EC2-005",),
    "AWS-0180": ("ASSAY-RDS-001",),
    "AWS-0080": ("ASSAY-RDS-002",),
    "AWS-0057": ("ASSAY-IAM-001", "ASSAY-IAM-002"),
    "AWS-0345": ("ASSAY-IAM-002",),
    "AWS-0065": ("ASSAY-KMS-001",),
    "AWS-0014": ("ASSAY-LOG-001",),
    "AWS-0016": ("ASSAY-LOG-002",),
    # Checkov.
    "CKV_AWS_20": ("ASSAY-S3-001",),
    "CKV_AWS_53": ("ASSAY-S3-002",),
    "CKV_AWS_54": ("ASSAY-S3-002",),
    "CKV_AWS_55": ("ASSAY-S3-002",),
    "CKV_AWS_56": ("ASSAY-S3-002",),
    "CKV2_AWS_6": ("ASSAY-S3-002",),
    "CKV_AWS_19": ("ASSAY-S3-003",),
    "CKV_AWS_145": ("ASSAY-S3-003",),
    "CKV_AWS_21": ("ASSAY-S3-004",),
    "CKV_AWS_18": ("ASSAY-S3-005",),
    "CKV_AWS_24": ("ASSAY-EC2-001",),
    "CKV_AWS_25": ("ASSAY-EC2-002",),
    "CKV_AWS_277": ("ASSAY-EC2-004",),
    "CKV_AWS_3": ("ASSAY-EC2-005",),
    "CKV_AWS_17": ("ASSAY-RDS-001",),
    "CKV_AWS_16": ("ASSAY-RDS-002",),
    "CKV_AWS_62": ("ASSAY-IAM-001",),
    "CKV_AWS_63": ("ASSAY-IAM-001", "ASSAY-IAM-002"),
    "CKV_AWS_286": ("ASSAY-IAM-001",),
    "CKV_AWS_289": ("ASSAY-IAM-001",),
    "CKV_AWS_290": ("ASSAY-IAM-001",),
    "CKV_AWS_355": ("ASSAY-IAM-001",),
    "CKV_AWS_7": ("ASSAY-KMS-001",),
    "CKV_AWS_67": ("ASSAY-LOG-001",),
    "CKV_AWS_36": ("ASSAY-LOG-002",),
}

# Terraform sub-resources that configure a bucket; folded onto the bucket of the same name.
_S3_SUBRESOURCE = re.compile(r"^aws_s3_bucket_[a-z_]+\.")


def _severity(raw: object) -> Severity:
    return _SEVERITY.get(str(raw or "").strip().lower(), Severity.INFO)


def _short_id(check_id: str) -> str:
    return check_id.removeprefix("AVD-")


def resource_key(resource_id: str) -> str:
    """Normalize a resource id for matching: lower case, no module path, bucket sub-resources folded."""
    key = resource_id.strip().lower()
    key = re.sub(r"^(module\.[^.]+\.)+", "", key)
    key = re.sub(r"\[[^\]]*\]$", "", key)
    if _S3_SUBRESOURCE.match(key):
        key = "aws_s3_bucket." + key.split(".", 1)[1]
    return key


def match_key(f: Finding) -> set[tuple[str, str]]:
    """Every (resource key, assay rule id) pair this finding stands for."""
    if f.source is Source.ASSAY:
        return {(resource_key(f.resource_id), f.rule_id)}
    rules = ASSAY_EQUIVALENT.get(_short_id(f.rule_id), ())
    return {(resource_key(f.resource_id), r) for r in rules}


def _finding(
    source: Source,
    *,
    rule_id: str,
    resource_id: str,
    resource_type: str,
    provider: str,
    title: str,
    severity: Severity,
    rationale: str,
    remediation: str,
    evidence: dict[str, Any],
    references: Sequence[str] = (),
    region: str = "global",
) -> Finding:
    equivalent = ASSAY_EQUIVALENT.get(_short_id(rule_id))
    if equivalent:
        evidence = {**evidence, "assay_equivalent": list(equivalent)}
    return Finding(
        rule_id=rule_id,
        resource_id=resource_id,
        resource_type=resource_type,
        provider=provider,
        region=region,
        title=title,
        severity_base=severity,
        rationale=rationale,
        impact=rationale,
        remediation=remediation,
        evidence=evidence,
        source=source,
        score=BAND_SCORE[severity],
        band=severity,
        references=[r for r in references if isinstance(r, str)],
    )


def _tf_type(resource: str) -> str:
    head = re.sub(r"^(module\.[^.]+\.)+", "", resource.strip().lower()).split(".", 1)[0]
    return f"terraform.{head}" if head.startswith(("aws_", "azurerm_", "google_")) else "iac.resource"


def _parse_trivy(data: Mapping[str, Any]) -> Iterator[Finding]:
    artifact_type = str(data.get("ArtifactType", ""))
    provider = {"container_image": "container", "filesystem": "filesystem", "repository": "filesystem"}.get(
        artifact_type, "iac"
    )
    for result in data.get("Results") or []:
        target = str(result.get("Target", ""))
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            resource = str(cause.get("Resource") or target)
            yield _finding(
                Source.TRIVY,
                rule_id=_short_id(str(m["ID"])),
                resource_id=resource,
                resource_type=_tf_type(resource) if result.get("Type") == "terraform" else f"iac.{result.get('Type')}",
                provider="terraform" if result.get("Type") == "terraform" else provider,
                title=str(m.get("Title", m["ID"])),
                severity=_severity(m.get("Severity")),
                rationale=str(m.get("Description", "")).strip(),
                remediation=str(m.get("Resolution", "")),
                evidence={
                    "file": target,
                    "start_line": cause.get("StartLine"),
                    "message": m.get("Message", ""),
                    "service": cause.get("Service", ""),
                },
                references=m.get("References") or [],
            )
        for v in result.get("Vulnerabilities") or []:
            pkg = f"{v.get('PkgName', '?')}@{v.get('InstalledVersion', '?')}"
            yield _finding(
                Source.TRIVY,
                rule_id=str(v["VulnerabilityID"]),
                resource_id=f"{target}:{pkg}",
                resource_type="package",
                provider=provider,
                title=str(v.get("Title") or v["VulnerabilityID"]),
                severity=_severity(v.get("Severity")),
                rationale=str(v.get("Description", "")).strip(),
                remediation=f"Upgrade {v.get('PkgName')} to {v['FixedVersion']}"
                if v.get("FixedVersion")
                else "No fixed version published",
                evidence={
                    "target": target,
                    "package": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "status": v.get("Status"),
                },
                references=[v["PrimaryURL"]] if v.get("PrimaryURL") else [],
            )
        for s in result.get("Secrets") or []:
            # The matched text is the secret itself, so only its location is kept.
            yield _finding(
                Source.TRIVY,
                rule_id=f"secret:{s.get('RuleID', 'unknown')}",
                resource_id=f"{target}:{s.get('StartLine', 0)}",
                resource_type="file",
                provider=provider,
                title=str(s.get("Title", "Secret")),
                severity=_severity(s.get("Severity")),
                rationale="A secret-like value is stored in the scanned content.",
                remediation="Remove the value, rotate it and load it from a secret store.",
                evidence={"file": target, "start_line": s.get("StartLine"), "category": s.get("Category")},
            )


def _checkov_reports(data: Any) -> Iterator[Mapping[str, Any]]:
    if isinstance(data, list):
        for item in data:
            yield from _checkov_reports(item)
    elif isinstance(data, Mapping) and "results" in data:
        yield data


def _parse_checkov(data: Any) -> Iterator[Finding]:
    for report in _checkov_reports(data):
        check_type = str(report.get("check_type", "iac"))
        for c in (report.get("results") or {}).get("failed_checks") or []:
            resource = str(c.get("resource", ""))
            lines = c.get("file_line_range") or [None]
            guideline = c.get("guideline")
            yield _finding(
                Source.CHECKOV,
                rule_id=str(c["check_id"]),
                resource_id=resource,
                resource_type=_tf_type(resource) if check_type == "terraform" else f"iac.{check_type}",
                provider="terraform" if check_type == "terraform" else check_type,
                title=str(c.get("check_name", c["check_id"])),
                # Checkov leaves severity empty without a platform key; medium is the neutral default.
                severity=_severity(c.get("severity") or "medium"),
                rationale=str(c.get("description") or c.get("check_name", "")),
                remediation=f"See {guideline}" if guideline else "",
                evidence={"file": str(c.get("file_path", "")).lstrip("/\\"), "start_line": lines[0]},
                references=[guideline] if guideline else [],
            )


def _parse_prowler(data: Any) -> Iterator[Finding]:
    items = data if isinstance(data, list) else [data]
    for item in items:
        if not isinstance(item, Mapping):
            continue
        if "finding_info" in item:
            yield from _prowler_ocsf(item)
        elif "CheckID" in item:
            yield from _prowler_native(item)


def _prowler_ocsf(item: Mapping[str, Any]) -> Iterator[Finding]:
    if str(item.get("status_code", "")).upper() != "FAIL":
        return
    info = item.get("finding_info") or {}
    meta = item.get("metadata") or {}
    remediation = item.get("remediation") or {}
    resources = item.get("resources") or [{}]
    cloud = item.get("cloud") or {}
    check = str(meta.get("event_code") or info.get("uid", "prowler-check"))
    for res in resources:
        rid = str(res.get("uid") or res.get("name") or "unknown")
        rtype = str(res.get("type") or "unknown")
        provider = str(cloud.get("provider") or "unknown")
        region = str(res.get("region") or cloud.get("region") or "global")
        evidence: dict[str, Any] = {"message": item.get("status_detail") or item.get("message", "")}
        # The IaC provider wraps Trivy; the Terraform address sits in the embedded Trivy result.
        cause = ((res.get("data") or {}).get("metadata") or {}).get("CauseMetadata") or {}
        if cause.get("Resource"):
            evidence |= {"file": rid, "start_line": cause.get("StartLine"), "service": cause.get("Service", "")}
            rid = str(cause["Resource"])
            rtype = _tf_type(rid)
            provider = "terraform" if (res.get("group") or {}).get("name") == "terraform" else provider
            region = "global"
        yield _finding(
            Source.PROWLER,
            rule_id=check,
            resource_id=rid,
            resource_type=rtype,
            provider=provider,
            region=region,
            title=str(info.get("title") or check),
            severity=_severity(item.get("severity")),
            rationale=str(info.get("desc") or item.get("risk_details") or "").strip(),
            remediation=str(remediation.get("desc", "")),
            evidence=evidence,
            references=remediation.get("references") or [],
        )


def _prowler_native(item: Mapping[str, Any]) -> Iterator[Finding]:
    if str(item.get("Status", "")).upper() != "FAIL":
        return
    rec = (item.get("Remediation") or {}).get("Recommendation") or {}
    check = str(item["CheckID"])
    yield _finding(
        Source.PROWLER,
        rule_id=check,
        resource_id=str(item.get("ResourceArn") or item.get("ResourceId") or "unknown"),
        resource_type=str(item.get("ResourceType") or "unknown"),
        provider=str(item.get("Provider") or "unknown"),
        region=str(item.get("Region") or "global"),
        title=str(item.get("CheckTitle") or check),
        severity=_severity(item.get("Severity")),
        rationale=str(item.get("Risk") or ""),
        remediation=str(rec.get("Text", "")),
        evidence={"message": item.get("StatusExtended", "")},
        references=[rec["Url"]] if rec.get("Url") else [],
    )


_PARSERS = {Source.TRIVY: _parse_trivy, Source.CHECKOV: _parse_checkov, Source.PROWLER: _parse_prowler}


def _openscap(path: Path) -> list[Finding]:
    # Lazy import so the other parsers work even if the XML stack is trimmed from an install.
    try:
        module = importlib.import_module("cspm.ingest.xccdf")
    except ModuleNotFoundError as exc:
        raise ValueError("OpenSCAP ingestion needs cspm.ingest.xccdf") from exc
    found: list[Finding] = list(module.parse_xccdf(path))
    return found


def _load(path: Path) -> Any:
    raw = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
    text = raw.decode("utf-8-sig")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Some tools write one JSON object per line.
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def _merge(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse repeats of the same id (Trivy reports one row per offending line)."""
    out: dict[str, Finding] = {}
    for f in findings:
        prior = out.get(f.id)
        if prior is None:
            out[f.id] = f
            continue
        lines = prior.evidence.setdefault("lines", [prior.evidence.get("start_line")])
        lines.append(f.evidence.get("start_line"))
    return list(out.values())


def ingest(tool: Source, path: Path, *, salt: str = "") -> list[Finding]:
    """Parse one tool output file into redacted Findings labelled with the tool as source."""
    if tool is Source.OPENSCAP:
        raw = _openscap(path)
    else:
        parser = _PARSERS.get(tool)
        if parser is None:
            raise ValueError(f"no parser for {tool.value}")
        raw = list(parser(_load(path)))
    red = Redactor(salt)
    findings = []
    for f in _merge(raw):
        f.resource_id = red.text(f.resource_id)
        f.evidence = red.value(f.evidence)
        f.rationale = red.text(f.rationale)
        f.impact = red.text(f.impact)
        findings.append(f)
    return findings


@dataclass(frozen=True, slots=True)
class DedupeResult:
    """Tool findings split into those that add something and those assay already reports."""

    unique: list[Finding]
    duplicates: list[tuple[Finding, str]]


def dedupe(tool_findings: Iterable[Finding], assay_findings: Iterable[Finding]) -> DedupeResult:
    """Drop tool findings whose (resource key, assay rule id) matches an assay finding."""
    seen: dict[tuple[str, str], str] = {}
    for a in assay_findings:
        for key in match_key(a):
            seen.setdefault(key, a.id)
    unique: list[Finding] = []
    dupes: list[tuple[Finding, str]] = []
    for f in tool_findings:
        hit = next((seen[k] for k in sorted(match_key(f)) if k in seen), None)
        if hit is None:
            unique.append(f)
        else:
            dupes.append((f, hit))
    return DedupeResult(unique, dupes)
