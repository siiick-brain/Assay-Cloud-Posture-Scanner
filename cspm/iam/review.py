"""Least-privilege review of one IAM policy against a workload requirement file."""

from __future__ import annotations

import difflib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from cspm.contracts.finding import Severity
from cspm.iam.patterns import PATTERNS

POLICY_VERSION = "2012-10-17"
_READ_PREFIXES = ("list", "get", "describe")


@dataclass(frozen=True, slots=True)
class IamIssue:
    kind: str
    severity: Severity
    detail: str
    statement: int | None = None
    actions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity.value,
            "detail": self.detail,
            "statement": self.statement,
            "actions": list(self.actions),
        }


@dataclass(slots=True)
class ReviewResult:
    issues: list[IamIssue]
    proposed_policy: dict[str, Any]
    diff: str
    missing: list[str] = field(default_factory=list)
    proposed_issues: list[IamIssue] = field(default_factory=list)

    @property
    def proposal_clean(self) -> bool:
        return not self.proposed_issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "issues": [i.to_dict() for i in self.issues],
            "missing": list(self.missing),
            "proposed_policy": self.proposed_policy,
            "proposed_issues": [i.to_dict() for i in self.proposed_issues],
            "diff": self.diff,
        }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _statements(policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = policy.get("Statement", [])
    if isinstance(raw, Mapping):
        return [dict(raw)]
    return [dict(s) for s in raw]


def _action_match(pattern: str, action: str) -> bool:
    # IAM action names are case-insensitive; ARNs are not.
    return fnmatchcase(action.lower(), pattern.lower())


def _covers_action(stmt: Mapping[str, Any], action: str) -> bool:
    if "NotAction" in stmt:
        return not any(_action_match(p, action) for p in _as_list(stmt["NotAction"]))
    return any(_action_match(p, action) for p in _as_list(stmt.get("Action")))


def _covers_resource(stmt: Mapping[str, Any], resource: str) -> bool:
    if "NotResource" in stmt:
        return not any(fnmatchcase(resource, p) for p in _as_list(stmt["NotResource"]))
    return any(fnmatchcase(resource, p) for p in _as_list(stmt.get("Resource")))


def _any_resource(stmt: Mapping[str, Any]) -> bool:
    return "NotResource" in stmt or "*" in _as_list(stmt.get("Resource"))


def _allows(stmts: Iterable[Mapping[str, Any]]) -> list[tuple[int, Mapping[str, Any]]]:
    return [(i, s) for i, s in enumerate(stmts) if s.get("Effect") == "Allow"]


def _is_read_only(action: str) -> bool:
    name = action.split(":", 1)[-1].lower()
    return "*" not in action and name.startswith(_READ_PREFIXES)


def _wildcard_issue(index: int, action: str, any_resource: bool) -> IamIssue | None:
    if "*" not in action and "?" not in action:
        return None
    if action == "*" and any_resource:
        return IamIssue("full_admin", Severity.CRITICAL, "Allows every action on every resource", index, (action,))
    if action in ("*", "*:*"):
        return IamIssue("action_wildcard", Severity.HIGH, "Allows every action", index, (action,))
    if action.endswith(":*"):
        return IamIssue("service_wildcard", Severity.MEDIUM, f"Allows every {action[:-2]} action", index, (action,))
    return IamIssue("partial_wildcard", Severity.LOW, f"Action pattern {action} may grow as AWS adds actions",
                    index, (action,))


def _statement_issues(index: int, stmt: Mapping[str, Any]) -> list[IamIssue]:
    issues: list[IamIssue] = []
    any_res = _any_resource(stmt)
    if "NotAction" in stmt:
        issues.append(IamIssue("not_action", Severity.HIGH, "Allow with NotAction grants everything not listed",
                               index, tuple(_as_list(stmt["NotAction"]))))
    if "NotResource" in stmt:
        issues.append(IamIssue("not_resource", Severity.MEDIUM, "Allow with NotResource covers every other resource",
                               index))
    actions = _as_list(stmt.get("Action"))
    for action in actions:
        found = _wildcard_issue(index, action, any_res)
        if found:
            issues.append(found)
    if "*" in _as_list(stmt.get("Resource")) and not any(i.kind == "full_admin" for i in issues):
        read_only = bool(actions) and all(_is_read_only(a) for a in actions)
        sev = Severity.LOW if read_only else Severity.MEDIUM
        issues.append(IamIssue("resource_wildcard", sev, "Statement applies to every resource", index,
                               tuple(actions)))
    return issues


def _escalation_issues(allows: list[tuple[int, Mapping[str, Any]]]) -> list[IamIssue]:
    issues: list[IamIssue] = []
    for pattern in PATTERNS:
        hits: list[str] = []
        for group in pattern.groups:
            hit = next(
                (
                    a
                    for a in group
                    for _, s in allows
                    if _covers_action(s, a) and (not pattern.needs_any_resource or _any_resource(s))
                ),
                None,
            )
            if hit is None:
                break
            hits.append(hit)
        else:
            issues.append(IamIssue("escalation", Severity.HIGH, f"{pattern.id}: {pattern.title}", None, tuple(hits)))
    return issues


def find_issues(policy: Mapping[str, Any]) -> list[IamIssue]:
    """Return wildcard, NotAction, NotResource and escalation issues in a policy."""
    allows = _allows(_statements(policy))
    issues: list[IamIssue] = []
    for index, stmt in allows:
        issues.extend(_statement_issues(index, stmt))
    issues.extend(_escalation_issues(allows))
    return issues


def _permissions(requirements: Mapping[str, Any]) -> list[dict[str, Any]]:
    perms = requirements.get("permissions")
    if not isinstance(perms, list) or not perms:
        raise ValueError("requirements need a non-empty 'permissions' list")
    out: list[dict[str, Any]] = []
    for n, entry in enumerate(perms):
        if not isinstance(entry, Mapping):
            raise ValueError(f"permissions[{n}] must be a mapping")
        actions = _as_list(entry.get("actions"))
        resources = _as_list(entry.get("resources"))
        if not actions or not resources:
            raise ValueError(f"permissions[{n}] needs actions and resources")
        out.append({"sid": entry.get("sid"), "actions": actions, "resources": resources})
    return out


def _beyond_issues(allows: list[tuple[int, Mapping[str, Any]]], perms: list[dict[str, Any]]) -> list[IamIssue]:
    need_actions = [a for p in perms for a in p["actions"]]
    need_resources = [r for p in perms for r in p["resources"]]
    issues: list[IamIssue] = []
    for index, stmt in allows:
        if "NotAction" in stmt:
            continue
        extra = [a for a in _as_list(stmt.get("Action")) if not any(_action_match(n, a) for n in need_actions)]
        if extra:
            issues.append(IamIssue("beyond_requirements", Severity.MEDIUM,
                                   "Actions not in the workload requirement file", index, tuple(extra)))
        # A granted pattern is inside the need only when a required pattern already matches it as text.
        wide = [r for r in _as_list(stmt.get("Resource")) if not any(fnmatchcase(r, n) for n in need_resources)]
        if wide:
            issues.append(IamIssue("resource_beyond_requirements", Severity.MEDIUM,
                                   "Resources not in the workload requirement file: " + ", ".join(wide), index))
    return issues


def _granted(allows: list[tuple[int, Mapping[str, Any]]], denies: Sequence[Mapping[str, Any]],
             action: str, resource: str) -> bool:
    if any(_covers_action(d, action) and _covers_resource(d, resource) for d in denies):
        return False
    return any(_covers_action(s, action) and _covers_resource(s, resource) for _, s in allows)


def _propose(policy: Mapping[str, Any], perms: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    stmts = _statements(policy)
    allows = _allows(stmts)
    denies = [s for s in stmts if s.get("Effect") == "Deny"]
    proposed: list[dict[str, Any]] = []
    missing: list[str] = []
    for n, perm in enumerate(perms):
        kept: list[str] = []
        for action in perm["actions"]:
            gaps = [r for r in perm["resources"] if not _granted(allows, denies, action, r)]
            if gaps:
                # Never widen: a need the current policy does not grant stays out of the proposal.
                missing.extend(f"{action} on {r}" for r in gaps)
            else:
                kept.append(action)
        if kept:
            resources = perm["resources"]
            proposed.append({
                "Sid": perm["sid"] or f"Need{n + 1}",
                "Effect": "Allow",
                "Action": sorted(set(kept), key=str.lower),
                "Resource": resources[0] if len(resources) == 1 else list(resources),
            })
    proposed.extend(denies)
    return {"Version": policy.get("Version", POLICY_VERSION), "Statement": proposed}, missing


def policy_diff(old: Mapping[str, Any], new: Mapping[str, Any]) -> str:
    """Unified diff of two policies rendered as indented JSON."""
    a = json.dumps(old, indent=2).splitlines()
    b = json.dumps(new, indent=2).splitlines()
    return "\n".join(difflib.unified_diff(a, b, fromfile="current", tofile="proposed", lineterm=""))


def review(policy: dict[str, Any], requirements: dict[str, Any]) -> ReviewResult:
    """Review a policy, propose a least-privilege version and diff the two."""
    if not isinstance(policy, Mapping) or "Statement" not in policy:
        raise ValueError("policy must be a mapping with a Statement")
    perms = _permissions(requirements)
    allows = _allows(_statements(policy))
    issues = find_issues(policy) + _beyond_issues(allows, perms)
    proposed, missing = _propose(policy, perms)
    return ReviewResult(
        issues=issues,
        proposed_policy=proposed,
        diff=policy_diff(policy, proposed),
        missing=missing,
        proposed_issues=find_issues(proposed),
    )
