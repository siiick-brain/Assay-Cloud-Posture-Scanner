"""IAM policy, user, role and account rules."""

from __future__ import annotations

import re
from typing import Any

from cspm.contracts.resource import Resource
from cspm.contracts.rule import ScanContext, Violation
from rules._base import (
    admin_statements,
    age_days,
    allow_statements,
    as_list,
    grants_full_admin,
    meta,
    statement_label,
    wildcard_principal_statements,
)

ADMIN_POLICY_SUFFIX = ":policy/AdministratorAccess"
KEY_MAX_AGE_DAYS = 90
MIN_PASSWORD_LENGTH = 14
_SERVICE_WILDCARD = re.compile(r"^[a-z0-9-]+:\*$")


class PolicyFullAdmin:
    meta = meta(
        "ASSAY-IAM-001",
        rationale="Action * on Resource * (or Allow with NotAction) hands out every permission in the account.",
        impact="Anyone holding the policy can read all data, create users and turn off logging.",
        remediation="Replace the statement with the specific actions and resources the workload needs.",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        # AWS managed policies such as AdministratorAccess exist in every account; only use of them matters.
        if cfg.get("aws_managed"):
            return []
        doc = cfg.get("document")
        labels = admin_statements(doc)
        if not labels:
            return []
        # A Condition narrows when the grant applies but still allows admin, so it is noted, not excused.
        conditional = [
            statement_label(i, s) for i, s in allow_statements(doc) if s.get("Condition") and grants_full_admin(s)
        ]
        evidence: dict[str, Any] = {
            "policy": cfg.get("name"),
            "statements": labels,
            "attached": bool(cfg.get("attached")),
        }
        if conditional:
            evidence["conditional_statements"] = conditional
        return [Violation(evidence=evidence, exposure="internal" if cfg.get("attached") else "none")]


class PolicyServiceWildcard:
    meta = meta(
        "ASSAY-IAM-002",
        rationale="A service:* action grants every present and future action of that service.",
        impact="Holders can perform destructive or privilege raising actions the workload never needed.",
        remediation="List the exact actions used; IAM Access Analyzer policy generation can help.",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if cfg.get("aws_managed"):
            return []
        wildcards: list[str] = []
        for _, stmt in allow_statements(cfg.get("document")):
            wildcards += [str(a) for a in as_list(stmt.get("Action")) if _SERVICE_WILDCARD.match(str(a).lower())]
        if not wildcards:
            return []
        evidence = {"policy": cfg.get("name"), "actions": sorted(set(wildcards)), "attached": bool(cfg.get("attached"))}
        return [Violation(evidence=evidence, exposure="internal" if cfg.get("attached") else "none")]


class UserDirectAdmin:
    meta = meta(
        "ASSAY-IAM-003",
        rationale="Admin rights attached straight to a user bypass group review and stay with that one identity.",
        impact="Compromise of this user's password or keys gives full control of the account.",
        remediation="Remove the direct attachment and grant admin through a role assumed with MFA.",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        attached = [str(a) for a in cfg.get("attached_policy_arns") or []]
        admin_customer = {
            str(r.config.get("arn"))
            for r in ctx.inventory
            if r.type == "aws.iam.policy" and admin_statements(r.config.get("document"))
        }
        via_attached = [a for a in attached if a.endswith(ADMIN_POLICY_SUFFIX) or a in admin_customer]
        via_inline = [
            str(p.get("name")) for p in cfg.get("inline_policies") or [] if admin_statements(p.get("document"))
        ]
        if not via_attached and not via_inline:
            return []
        evidence = {"user": cfg.get("name"), "admin_policy_arns": via_attached, "admin_inline_policies": via_inline}
        return [Violation(evidence=evidence, exposure="internal")]


class ConsoleUserNoMfa:
    meta = meta(
        "ASSAY-IAM-004",
        rationale="A console password alone falls to phishing, reuse and guessing.",
        impact="A stolen password gives console access with this user's permissions.",
        remediation="Enroll an MFA device (phishing resistant if possible) and require MFA in policies.",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        cfg = resource.config
        if not cfg.get("has_console_password") or int(cfg.get("mfa_devices") or 0) > 0:
            return []
        return [Violation(evidence={"user": cfg.get("name"), "mfa_devices": 0}, exposure="internet")]


class OldAccessKey:
    meta = meta(
        "ASSAY-IAM-005",
        rationale="Long lived keys end up in scripts, laptops and repos; age raises the odds one has leaked.",
        impact="A leaked key works from anywhere until it is rotated.",
        remediation="Rotate the key, delete the old one and move workloads to roles with temporary credentials.",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        old = []
        for key in resource.config.get("access_keys") or []:
            age = age_days(key.get("created"), ctx.now)
            if key.get("status") == "Active" and age is not None and age > KEY_MAX_AGE_DAYS:
                old.append({"key_id_suffix": key.get("key_id_suffix"), "age_days": int(age)})
        if not old:
            return []
        return [Violation(evidence={"user": resource.config.get("name"), "old_keys": old}, exposure="internet")]


class RoleWildcardTrust:
    meta = meta(
        "ASSAY-IAM-006",
        rationale="A trust policy open to any principal lets any AWS account assume the role.",
        impact="Outsiders can obtain temporary credentials with the role's permissions.",
        remediation="Name the trusted accounts or services, or add conditions such as aws:PrincipalOrgID.",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        labels = wildcard_principal_statements(resource.config.get("trust_policy"))
        if not labels:
            return []
        return [Violation(evidence={"role": resource.config.get("name"), "statements": labels}, exposure="internet")]


class RootAccessKeys:
    meta = meta(
        "ASSAY-IAM-007",
        rationale="Root keys cannot be limited by any policy and are rarely needed.",
        impact="A leaked root key is a full and unrestricted takeover of the account.",
        remediation="Delete root access keys and use IAM roles for all programmatic work.",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        if not resource.config.get("root_access_keys_present"):
            return []
        return [Violation(evidence={"root_access_keys_present": True}, exposure="internet")]


class WeakPasswordPolicy:
    meta = meta(
        "ASSAY-IAM-008",
        rationale="Without a policy of at least 14 characters users may pick short, guessable passwords.",
        impact="Console passwords are easier to guess or crack.",
        remediation="Set an account password policy with a minimum length of 14 or more.",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        policy = resource.config.get("password_policy")
        if not policy:
            return [Violation(evidence={"password_policy": None})]
        length = int(policy.get("minimum_length") or 0)
        if length >= MIN_PASSWORD_LENGTH:
            return []
        return [Violation(evidence={"minimum_length": length, "required": MIN_PASSWORD_LENGTH})]
