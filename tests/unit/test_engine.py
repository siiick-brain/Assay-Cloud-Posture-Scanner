from __future__ import annotations

from typing import Any

from cspm.contracts import Finding, Provider, Resource, ScanContext, Severity, Violation
from cspm.engine import _merge, run_rules
from tests.unit.test_rules_cases import ADMIN, CTX, doc, make, sg_rule


def test_clean_resources_give_no_findings() -> None:
    resources = [make("aws.s3.bucket"), make("aws.ec2.security_group"), make("azure.keyvault.vault")]
    assert run_rules(resources, CTX) == []


def test_findings_carry_meta_score_and_controls() -> None:
    sg = make("aws.ec2.security_group", tags={"criticality": "high"}, ingress=[sg_rule()])
    (finding,) = run_rules([sg], CTX)
    assert isinstance(finding, Finding)
    assert finding.rule_id == "ASSAY-EC2-001"
    assert finding.resource_id == sg.id
    assert finding.provider == "aws"
    assert finding.severity_base is Severity.HIGH
    assert finding.evidence["exposure"] == "internet"
    assert finding.score == 9.5 and finding.band is Severity.CRITICAL
    frameworks = {c.framework for c in finding.controls}
    assert {"nist-800-53", "iso-27001", "cis-aws-foundations"} <= frameworks
    assert finding.first_seen == CTX.now
    assert len(finding.id) == 16


def test_inventory_defaults_to_scanned_resources() -> None:
    policy = make("aws.iam.policy", document=doc(ADMIN))
    user = make("aws.iam.user", attached_policy_arns=[policy.config["arn"]])
    rules = {f.rule_id for f in run_rules([policy, user], CTX)}
    assert "ASSAY-IAM-003" in rules
    explicit = ScanContext(now=CTX.now, mode=CTX.mode, inventory=(user,))
    assert "ASSAY-IAM-003" not in {f.rule_id for f in run_rules([policy, user], explicit)}


def test_unknown_resource_type_is_ignored() -> None:
    assert run_rules([Resource(id="x", type="aws.lambda.function", provider=Provider.AWS, region="r")], CTX) == []


def test_multiple_violations_merge_into_one_finding() -> None:
    merged = _merge([Violation(evidence={"a": 1}), Violation(evidence={"b": 2}, exposure="internet")])
    assert merged.exposure == "internet"
    evidence: Any = merged.evidence
    assert evidence["violations"] == [{"a": 1}, {"b": 2}]
    single = Violation(evidence={"a": 1})
    assert _merge([single]) is single


def test_finding_ids_unique_per_rule_and_resource() -> None:
    bucket = make(
        "aws.s3.bucket", encryption=None, versioning="Disabled", logging_enabled=False, public_access_block={}
    )
    findings = run_rules([bucket], CTX)
    assert len({f.id for f in findings}) == len(findings) == 4
