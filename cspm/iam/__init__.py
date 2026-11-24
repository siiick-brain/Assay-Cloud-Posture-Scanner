"""IAM least-privilege review."""

from cspm.iam.cli import main_iam_review
from cspm.iam.patterns import PATTERNS, EscalationPattern
from cspm.iam.review import IamIssue, ReviewResult, find_issues, policy_diff, review

__all__ = [
    "PATTERNS",
    "EscalationPattern",
    "IamIssue",
    "ReviewResult",
    "find_issues",
    "main_iam_review",
    "policy_diff",
    "review",
]
