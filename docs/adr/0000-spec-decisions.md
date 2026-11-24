# ADR 0000: Scope decisions

Status: accepted, 2026-11-23

These choices fix the scope written in docs/spec.md.

| Question | Decision | Why |
|---|---|---|
| Cloud scope | AWS first, Azure second through the same collector interface | The testbed and boto3 are AWS shaped. Azure has no free control-plane emulator. |
| Emulator | Moto (see ADR 0003) | No account, no token, Apache-2.0. |
| Azure coverage | Synthetic JSON fixtures in testbed/azure-fixtures. Live SDK path is Not verified. | No free ARM emulator. Azurite covers data plane only. |
| Frameworks | Seven framework families, identifiers only | Each rule must hit at least three. |
| Scoring | 0 to 10 with five bands, documented rubric, no CVSS | Posture findings have no exploit vector to score. |
| Rule format | Python classes registered by rule ID | Easier to test and type check than YAML expressions. |
| Tooling | Python 3.12, uv, pytest, Hypothesis, ruff, mypy strict | uv gives a hashed lockfile for free. |
| testbed/ vs fixtures/ | testbed/ holds Terraform and Azure seed JSON. fixtures/ holds recorded tool output. | Different lifecycles. |
| Rules package | Top-level package `rules` shipped next to `cspm` | Keeps rule files easy to find. |
| Clock | Rules read `ScanContext.now` and never call the system clock | Lets the testbed reach "old key" and "expiring cert" states without waiting. |
| Licence | MIT | Permissive and matches most tools used. |
