"""Privilege escalation patterns used by the IAM review.

Written for this project from how the IAM APIs behave. Each pattern lists groups
of actions; a policy matches when it grants at least one action from every group.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EscalationPattern:
    id: str
    title: str
    groups: tuple[tuple[str, ...], ...]
    # Some actions are only dangerous when the resource is open, such as assuming any role.
    needs_any_resource: bool = False


_COMPUTE_WITH_ROLE = (
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "ecs:RunTask",
    "ecs:RegisterTaskDefinition",
    "glue:CreateDevEndpoint",
    "glue:CreateJob",
    "cloudformation:CreateStack",
    "sagemaker:CreateNotebookInstance",
    "codebuild:CreateProject",
    "datapipeline:CreatePipeline",
)

PATTERNS: tuple[EscalationPattern, ...] = (
    EscalationPattern(
        "ESC-PASSROLE-COMPUTE",
        "Pass a role to new compute and run code as that role",
        (("iam:PassRole",), _COMPUTE_WITH_ROLE),
    ),
    EscalationPattern(
        "ESC-PASSROLE-LAMBDA-UPDATE",
        "Pass a role and change Lambda code or config to run as it",
        (("iam:PassRole",), ("lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration")),
    ),
    EscalationPattern(
        "ESC-LAMBDA-CODE",
        "Replace the code of an existing function that already has a role",
        (("lambda:UpdateFunctionCode",),),
    ),
    EscalationPattern(
        "ESC-POLICY-VERSION",
        "Publish a new default version of a managed policy",
        (("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"),),
    ),
    EscalationPattern(
        "ESC-ATTACH-POLICY",
        "Attach any managed policy to a principal",
        (("iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy"),),
    ),
    EscalationPattern(
        "ESC-INLINE-POLICY",
        "Write an inline policy onto a principal",
        (("iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy"),),
    ),
    EscalationPattern(
        "ESC-CREDENTIALS",
        "Mint credentials or a console password for another user",
        (("iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"),),
    ),
    EscalationPattern(
        "ESC-GROUP-JOIN",
        "Add a user to a more privileged group",
        (("iam:AddUserToGroup",),),
    ),
    EscalationPattern(
        "ESC-TRUST-EDIT",
        "Rewrite a role trust policy and then assume the role",
        (("iam:UpdateAssumeRolePolicy",), ("sts:AssumeRole",)),
    ),
    EscalationPattern(
        "ESC-ASSUME-ANY",
        "Assume any role in the account",
        (("sts:AssumeRole",),),
        needs_any_resource=True,
    ),
)
