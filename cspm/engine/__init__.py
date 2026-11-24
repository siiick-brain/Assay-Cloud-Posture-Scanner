"""Runs rules over resources and builds scored, mapped findings."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from cspm.contracts.finding import Finding
from cspm.contracts.resource import Resource
from cspm.contracts.rule import Rule, ScanContext, Violation
from cspm.contracts.rule_ids import EXPOSURE_LEVELS
from cspm.mapping import controls_for
from cspm.scoring import score
from rules import rules_for_type


def _merge(violations: Sequence[Violation]) -> Violation:
    """One finding per rule and resource keeps finding IDs unique for the store."""
    if len(violations) == 1:
        return violations[0]
    exposure = max((v.exposure for v in violations), key=EXPOSURE_LEVELS.index)
    return Violation(evidence={"violations": [dict(v.evidence) for v in violations]}, exposure=exposure)


def build_finding(rule: Rule, resource: Resource, violation: Violation, ctx: ScanContext) -> Finding:
    """Turn one violation into a Finding with score, band and control references."""
    m = rule.meta
    finding = Finding(
        rule_id=m.id,
        resource_id=resource.id,
        resource_type=resource.type,
        provider=resource.provider.value,
        region=resource.region,
        title=m.title,
        severity_base=m.severity_base,
        rationale=m.rationale,
        impact=m.impact,
        remediation=m.remediation,
        evidence={**dict(violation.evidence), "exposure": violation.exposure},
        references=list(m.references),
        controls=controls_for(m.id),
        first_seen=ctx.now,
        last_seen=ctx.now,
    )
    value, band = score(finding, resource, violation.exposure)
    return replace(finding, score=value, band=band)


def run_rules(resources: Sequence[Resource], ctx: ScanContext) -> list[Finding]:
    """Evaluate every registered rule on matching resources.

    When ctx.inventory is empty the scanned resources stand in for it, so account
    level rules can see the other resources without the caller passing them twice.
    """
    if not ctx.inventory:
        ctx = replace(ctx, inventory=tuple(resources))
    findings: list[Finding] = []
    for resource in resources:
        for rule in rules_for_type(resource.type):
            violations = rule.evaluate(resource, ctx)
            if violations:
                findings.append(build_finding(rule, resource, _merge(violations), ctx))
    return findings


__all__ = ["build_finding", "run_rules"]
