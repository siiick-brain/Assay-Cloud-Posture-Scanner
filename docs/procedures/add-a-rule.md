# Add a rule

Use this when a new misconfiguration needs a check. A rule reads one resource type and returns violations. It never calls a cloud API.

## Before you start
- The rule ID must already exist in cspm/contracts/rule_ids.py. That list is frozen at contracts-v1. A new ID goes in first as its own small change.
- The rule may only read the config keys listed for its resource type in docs/contracts.md. A new key is also a contract change and the collector has to fill it.

## Steps
1. Create the rule class under rules/ next to the other rules for the same service. Set `meta` (ID, title, resource type, base severity, rationale and remediation) and implement `evaluate(resource, ctx)`.
2. Return one `Violation` per problem and set `exposure` to none, internal or internet. Scoring uses it, so pick the honest value.
3. Add a positive fixture (the rule fires) and a negative fixture (it stays quiet) to the rule tests. Gate G06 needs both.
4. Map the rule to at least three frameworks in mappings/. See add-a-framework-mapping.md.
5. If the testbed should seed this issue, add it to testbed/insecure, fix it in testbed/secure and list it in testbed/ground-truth.yaml. The scheduled regression workflow reads that file, so the expected count updates itself.
6. Regenerate docs/rules.md from code.
7. Run the checks:

```sh
uv run pytest -q --tb=short
uv run ruff check . --output-format concise
uv run mypy
uv run python scripts/check_allowlist.py
pwsh scripts/check-style.ps1 rules docs
```

## Done when
The new tests pass, the mapping coverage test passes and the secure testbed still gives zero findings.
