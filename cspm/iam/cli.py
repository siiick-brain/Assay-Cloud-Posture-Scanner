"""Entry point behind `cspm iam-review <policy.json> --requirements <req.yaml>`."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from cspm.iam.review import ReviewResult, review


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cspm iam-review", description="Least-privilege review of one IAM policy.")
    p.add_argument("policy", type=Path, help="policy document as JSON")
    p.add_argument("--requirements", type=Path, required=True, help="workload requirement file as YAML")
    p.add_argument("--out", type=Path, help="write the proposed policy JSON here")
    p.add_argument("--json", action="store_true", help="print the full result as JSON")
    return p


def _render(result: ReviewResult) -> str:
    lines = [f"Issues in current policy: {len(result.issues)}"]
    lines += [f"  [{i.severity.value}] {i.kind}: {i.detail} {', '.join(i.actions)}".rstrip() for i in result.issues]
    if result.missing:
        lines.append("Needed but not granted today (left out of the proposal):")
        lines += [f"  {m}" for m in result.missing]
    lines.append(f"Issues in proposed policy: {len(result.proposed_issues)}")
    lines += [f"  [{i.severity.value}] {i.kind}: {i.detail}" for i in result.proposed_issues]
    lines += ["", result.diff]
    return "\n".join(lines)


def main_iam_review(argv: Sequence[str] | None = None) -> int:
    """Run the review. Exit 0 when the current policy is clean, 1 when issues exist, 2 on bad input."""
    args = _parser().parse_args(argv)
    try:
        policy: Any = json.loads(args.policy.read_text(encoding="utf-8"))
        requirements: Any = yaml.safe_load(args.requirements.read_text(encoding="utf-8"))
        if not isinstance(policy, dict) or not isinstance(requirements, dict):
            raise ValueError("policy and requirements must both be mappings")
        result = review(policy, requirements)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"iam-review: {exc}", file=sys.stderr)
        return 2
    if args.out:
        args.out.write_text(json.dumps(result.proposed_policy, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result.to_dict(), indent=2) if args.json else _render(result))
    return 1 if result.issues else 0
