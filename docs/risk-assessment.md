# Risk assessment

Scope: risks that the scanner itself creates for the people who run it and for the accounts it reads. Cloud misconfigurations the scanner finds are out of scope here. The threats come from docs/threat-model.md.

Likelihood and impact use a 1 to 3 scale. Risk is likelihood times impact: 1 to 2 low, 3 to 4 medium, 6 to 9 high. Ratings are after the listed controls.

| ID | Risk | L | I | Risk | Controls in place | Residual note |
|---|---|---|---|---|---|---|
| R01 | Scanner code calls a write API and changes the scanned account | 1 | 3 | 3 medium | Runtime allowlist hook, static allowlist check in CI, read-only role | A bug in the hook itself would bypass layer one. Layer two and the role remain |
| R02 | Live credentials leak from the operator machine | 2 | 3 | 6 high | Env only, short sessions, never logged, gitleaks pre-commit and CI | Depends on operator discipline. No technical fix on our side |
| R03 | Findings store or reports leak and map every weakness of an account | 2 | 2 | 4 medium | Redaction of IDs and ARNs, artifacts/ and private/ ignored, local files only | Unredacted local copies still exist on the operator disk |
| R04 | Secret values copied into evidence | 1 | 3 | 3 medium | GetSecretValue, GetObject and Decrypt denied. Evidence redaction | Redaction is pattern based and can miss an unusual format |
| R05 | Testbed applied to a real account by a wrong endpoint | 1 | 3 | 3 medium | Testbed mode refuses non-emulator hosts. Endpoint hardcoded in Terraform | A manual terraform apply outside the scanner skips the scanner's check |
| R06 | Compromised dependency or action runs in CI | 2 | 2 | 4 medium | Hash-locked uv.lock, actions pinned by SHA, `permissions: {}` default, no cloud secrets in CI | A pinned SHA can still be malicious if it was bad when pinned |
| R07 | False negative gives an operator false confidence | 2 | 2 | 4 medium | Ground truth recall test, scheduled regression oracle, tool comparison with Trivy and Prowler | Rules only cover the seeded issue types. README limits section says so |
| R08 | False positive wastes triage time | 2 | 1 | 2 low | Negative fixture per rule, secure testbed must give zero findings | |
| R09 | Report tampered with after the scan | 1 | 2 | 2 low | SHA-256 manifest per report set | Manifest is not signed, so an attacker with write access can rewrite both |
| R10 | OpenSCAP results misread as a CIS compliance statement | 2 | 2 | 4 medium | docs/hardening.md says CIS-aligned profile only and lists not applicable rules | Readers skim. Wording repeated in README |
| R11 | Scanner image ships a known vulnerable package | 2 | 2 | 4 medium | Trivy image scan in CI, non-root user, read-only root filesystem, SBOM per build | Weekly schedule means a gap of up to seven days |

## Accepted risks
- R02 stays high. The scanner cannot protect credentials that the operator handles outside it. The procedure in docs/procedures/rotate-scanner-credentials.md is the mitigation.
- R09 stays as is. Signing reports needs key management that is out of scope for this project.

## Review
Revisit this table when a new collector, a new output format or a new CI job is added. Last review: 2026-11-24, after the evaluation in docs/evaluation.md. No rating changed.
