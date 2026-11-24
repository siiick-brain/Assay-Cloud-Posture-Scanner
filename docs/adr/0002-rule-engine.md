# ADR 0002: Rule engine

Status: accepted, 2026-11-23

Context: the project needs at least 25 rules that are easy to test one by one and to type check.

Decision: rules are Python classes that satisfy the `Rule` protocol in cspm/contracts/rule.py. Each has a `RuleMeta` with a frozen ID from rule_ids.py and an `evaluate(resource, ctx)` method that returns a list of `Violation`. The engine indexes rules by resource type, runs them and builds `Finding` objects. Rules read time only from `ScanContext.now`. Account-level rules may read `ctx.inventory`.

Rejected: YAML or Rego rules. They are shorter for simple checks but weaker for IAM policy parsing and harder to cover with mypy strict.

Consequences: a rule is one class plus two tests. docs/rules.md is generated from the metadata.
