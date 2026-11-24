from __future__ import annotations

import importlib
import inspect
import json
import pkgutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from cspm.contracts.finding import ScanMode, Severity
from cspm.contracts.resource import Provider, Resource
from cspm.contracts.rule import RuleMeta, ScanContext
from cspm.iam import PATTERNS, find_issues, main_iam_review, review

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "iam"
POLICY = EXAMPLES / "report-uploader-policy.json"
REQS = EXAMPLES / "report-uploader-requirements.yaml"
PROPOSED = EXAMPLES / "report-uploader-proposed.json"
BUCKET = "arn:aws:s3:::b/*"


def _policy(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(action: Any, resource: Any = "*", **extra: Any) -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def _kinds(policy: dict[str, Any]) -> set[str]:
    return {i.kind for i in find_issues(policy)}


def _example() -> tuple[dict[str, Any], dict[str, Any]]:
    return json.loads(POLICY.read_text()), yaml.safe_load(REQS.read_text())


def test_full_admin_is_critical() -> None:
    issues = find_issues(_policy(_allow("*")))
    assert [i.kind for i in issues if i.severity is Severity.CRITICAL] == ["full_admin"]


def test_wildcard_levels() -> None:
    assert "action_wildcard" in _kinds(_policy(_allow("*", BUCKET)))
    assert "service_wildcard" in _kinds(_policy(_allow("s3:*", BUCKET)))
    assert "partial_wildcard" in _kinds(_policy(_allow("s3:Get*", BUCKET)))


def test_resource_wildcard_severity_depends_on_actions() -> None:
    read = [i for i in find_issues(_policy(_allow(["ec2:DescribeInstances"]))) if i.kind == "resource_wildcard"]
    write = [i for i in find_issues(_policy(_allow(["s3:PutObject"]))) if i.kind == "resource_wildcard"]
    assert read[0].severity is Severity.LOW
    assert write[0].severity is Severity.MEDIUM


def test_not_action_and_not_resource() -> None:
    stmt = {"Effect": "Allow", "NotAction": "iam:*", "NotResource": "arn:aws:s3:::secret/*"}
    kinds = _kinds(_policy(stmt))
    assert {"not_action", "not_resource"} <= kinds
    # NotAction outside iam still grants sts:AssumeRole on an open resource.
    assert "escalation" in kinds


def test_deny_statements_are_not_flagged() -> None:
    assert find_issues(_policy({"Effect": "Deny", "Action": "*", "Resource": "*"})) == []


def test_single_statement_dict_is_accepted() -> None:
    assert _kinds({"Statement": _allow("s3:GetObject", BUCKET)}) == set()


@pytest.mark.parametrize(
    ("actions", "pattern_id"),
    [
        (["iam:PassRole", "ec2:RunInstances"], "ESC-PASSROLE-COMPUTE"),
        (["iam:PassRole", "lambda:UpdateFunctionConfiguration"], "ESC-PASSROLE-LAMBDA-UPDATE"),
        (["iam:CreatePolicyVersion"], "ESC-POLICY-VERSION"),
        (["iam:AttachUserPolicy"], "ESC-ATTACH-POLICY"),
        (["iam:PutRolePolicy"], "ESC-INLINE-POLICY"),
        (["iam:CreateAccessKey"], "ESC-CREDENTIALS"),
        (["iam:AddUserToGroup"], "ESC-GROUP-JOIN"),
        (["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"], "ESC-TRUST-EDIT"),
        (["sts:AssumeRole"], "ESC-ASSUME-ANY"),
        (["iam:*"], "ESC-ATTACH-POLICY"),
    ],
)
def test_escalation_patterns(actions: list[str], pattern_id: str) -> None:
    details = [i.detail for i in find_issues(_policy(_allow(actions))) if i.kind == "escalation"]
    assert any(d.startswith(pattern_id) for d in details)


def test_escalation_combination_spans_statements() -> None:
    policy = _policy(_allow("iam:PassRole", "arn:aws:iam::123456789012:role/app"), _allow("ec2:RunInstances"))
    assert any("ESC-PASSROLE-COMPUTE" in i.detail for i in find_issues(policy))


def test_assume_role_on_one_role_is_fine() -> None:
    policy = _policy(_allow("sts:AssumeRole", "arn:aws:iam::123456789012:role/reader"))
    assert _kinds(policy) == set()


def test_passrole_alone_is_not_escalation() -> None:
    assert "escalation" not in _kinds(_policy(_allow("iam:PassRole", "arn:aws:iam::123456789012:role/app")))


def test_pattern_ids_are_unique() -> None:
    ids = [p.id for p in PATTERNS]
    assert len(ids) == len(set(ids))


def test_review_example_flags_and_proposes() -> None:
    policy, reqs = _example()
    result = review(policy, reqs)
    kinds = {i.kind for i in result.issues}
    assert {"service_wildcard", "resource_wildcard", "escalation", "beyond_requirements",
            "resource_beyond_requirements"} <= kinds
    assert result.missing == []
    assert result.proposal_clean
    assert result.proposed_policy == json.loads(PROPOSED.read_text())
    assert result.diff.startswith("--- current\n+++ proposed")
    assert '-      "Action": "s3:*",' in result.diff


def test_proposal_never_widens() -> None:
    policy = _policy(_allow("s3:GetObject", BUCKET))
    reqs = {"permissions": [{"actions": ["s3:GetObject", "s3:PutObject"], "resources": [BUCKET]}]}
    result = review(policy, reqs)
    assert result.missing == [f"s3:PutObject on {BUCKET}"]
    assert result.proposed_policy["Statement"][0]["Action"] == ["s3:GetObject"]


def test_deny_blocks_and_is_carried_over() -> None:
    deny = {"Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"}
    policy = _policy(_allow("s3:*", BUCKET), deny)
    reqs = {"permissions": [{"actions": ["s3:PutObject"], "resources": [BUCKET]},
                            {"actions": ["s3:GetObject"], "resources": [BUCKET, "arn:aws:s3:::b"]}]}
    result = review(policy, reqs)
    assert f"s3:PutObject on {BUCKET}" in result.missing
    assert "s3:GetObject on arn:aws:s3:::b" in result.missing
    assert result.proposed_policy["Statement"] == [deny]


def test_multi_resource_need_keeps_list_and_not_resource_grant() -> None:
    policy = _policy({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret/*"})
    reqs = {"permissions": [{"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::a/*", "arn:aws:s3:::c/*"]}]}
    stmt = review(policy, reqs).proposed_policy["Statement"][0]
    assert stmt["Resource"] == ["arn:aws:s3:::a/*", "arn:aws:s3:::c/*"]
    assert stmt["Sid"] == "Need1"


def test_requirement_wildcard_covers_granted_action() -> None:
    policy = _policy(_allow("s3:GetObject", BUCKET))
    result = review(policy, {"permissions": [{"actions": ["s3:Get*"], "resources": ["arn:aws:s3:::*"]}]})
    assert not [i for i in result.issues if "beyond" in i.kind]


@pytest.mark.parametrize(
    "reqs",
    [{}, {"permissions": []}, {"permissions": ["x"]}, {"permissions": [{"actions": ["s3:GetObject"]}]}],
)
def test_bad_requirements(reqs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="permissions"):
        review(_policy(_allow("s3:GetObject")), reqs)


def test_bad_policy() -> None:
    with pytest.raises(ValueError, match="Statement"):
        review({"Version": "2012-10-17"}, {"permissions": [{"actions": ["a:b"], "resources": ["*"]}]})


def test_cli_text_and_out(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "proposed.json"
    assert main_iam_review([str(POLICY), "--requirements", str(REQS), "--out", str(out)]) == 1
    text = capsys.readouterr().out
    assert "Issues in proposed policy: 0" in text
    assert json.loads(out.read_text()) == json.loads(PROPOSED.read_text())


def test_cli_json_and_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps(_policy(_allow("s3:GetObject", BUCKET))))
    req = tmp_path / "r.yaml"
    req.write_text(yaml.safe_dump({"permissions": [{"actions": ["s3:GetObject", "s3:PutObject"],
                                                    "resources": [BUCKET]}]}))
    assert main_iam_review([str(pol), "--requirements", str(req)]) == 0
    assert "Needed but not granted" in capsys.readouterr().out
    assert main_iam_review([str(pol), "--requirements", str(req), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["missing"] == [f"s3:PutObject on {BUCKET}"]


def test_cli_bad_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    assert main_iam_review([str(bad), "--requirements", str(REQS)]) == 2
    assert main_iam_review([str(tmp_path / "nope.json"), "--requirements", str(REQS)]) == 2
    assert "iam-review:" in capsys.readouterr().err


def test_example_proposal_passes_own_detector() -> None:
    proposed = json.loads(PROPOSED.read_text())
    assert find_issues(proposed) == []
    actions = [a for s in proposed["Statement"] if s["Effect"] == "Allow" for a in s["Action"]]
    assert not [a for a in actions if "*" in a]


def _registered_rules() -> dict[str, Any]:
    """Find rule objects by walking the rules package."""
    found: dict[str, Any] = {}
    pkg = importlib.import_module("rules")
    for info in pkgutil.walk_packages(pkg.__path__, "rules."):
        module = importlib.import_module(info.name)
        for _, obj in inspect.getmembers(module):
            meta = getattr(obj, "meta", None)
            if not isinstance(meta, RuleMeta):
                continue
            rule = obj
            if inspect.isclass(obj):
                try:
                    rule = obj()
                except TypeError:
                    continue
            found[meta.id] = rule
    return found


def test_example_proposal_passes_lane_c_iam_rules() -> None:
    rules = _registered_rules()
    wanted = ("ASSAY-IAM-001", "ASSAY-IAM-002")
    if not all(r in rules for r in wanted):
        pytest.skip("ASSAY-IAM-001 and ASSAY-IAM-002 are not registered in rules yet")
    ctx = ScanContext(now=datetime(2026, 11, 23, tzinfo=UTC), mode=ScanMode.FIXTURE)

    def resource(doc: dict[str, Any]) -> Resource:
        config = {"name": "report-uploader", "arn": "arn:aws:iam::123456789012:policy/report-uploader",
                  "document": doc, "attached": True, "aws_managed": False}
        return Resource(id=config["arn"], type="aws.iam.policy", provider=Provider.AWS, region="global",
                        config=config)

    proposed, original = json.loads(PROPOSED.read_text()), json.loads(POLICY.read_text())
    for rule_id in wanted:
        assert rules[rule_id].evaluate(resource(proposed), ctx) == []
    # The original grants s3:* so the service wildcard rule must fire on it.
    assert rules["ASSAY-IAM-002"].evaluate(resource(original), ctx)
