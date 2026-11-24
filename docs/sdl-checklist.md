# Secure development checklist

Informed by the practice areas of IEC 62443-4-1. The wording below is ours and describes what this project does. It is not a claim of conformity with the standard.

Status: Done, Partial or Planned. Evidence points to a file or a CI job.

| Practice area | What we do | Evidence | Status |
|---|---|---|---|
| Security management (SM) | One owner, written style and design rules, tool list with versions and licences | docs/STYLE.md, docs/adr/, docs/references.md | Done |
| SM: secure environment | Dev and CI never hold cloud credentials. Tests use Moto and fixtures | .github/workflows/ci.yml emulator job | Done |
| SM: dependency control | Locked dependencies with hashes, actions pinned by commit SHA, SBOM per run | uv.lock, .github/workflows/security.yml sbom job | Done |
| Security requirements (SR) | Numbered security requirements with a verification method each | docs/requirements.md, scripts/trace.ps1 | Done |
| SR: threat model | STRIDE table and a credential theft attack tree | docs/threat-model.md | Done |
| Secure by design (SD) | Read-only by design with two enforcement layers, frozen contracts between modules | docs/adr/0004-read-only-enforcement.md, docs/contracts.md | Done |
| SD: defence in depth | Runtime hook, static check and read-only role. Non-root image with read-only root filesystem | scripts/check_allowlist.py, Dockerfile | Done |
| Secure implementation (SI) | Coding rules, ruff with security rules, mypy strict, style and authorship checks | pyproject.toml, docs/STYLE.md, ci.yml | Done |
| SI: secrets | gitleaks in the pre-commit hook and in CI | .githooks/pre-commit, security.yml gitleaks job | Done |
| Verification and validation (SVV) | Unit, property and integration tests, 85 percent coverage gate | ci.yml tests job | Partial: 98.4 percent measured locally, not yet run in CI |
| SVV: security testing | Write-block test, endpoint refusal test, allowlist static check, Trivy config and image scans | ci.yml allowlist job, security.yml | Partial: image scan waits for the Dockerfile |
| SVV: regression | Weekly testbed oracle, secure zero and insecure equal to ground truth | .github/workflows/regression.yml | Partial: secure 0 and insecure 16 locally, not yet run in CI |
| Defect management (DM) | Private advisory channel, findings tracked through a lifecycle with verification status | SECURITY.md, docs/procedures/handle-a-finding.md | Done |
| DM: disclosure | Fixes and advisories noted in the changelog | CHANGELOG.md | Planned |
| Security update management (SUM) | Dependency and image rescans on a weekly schedule | security.yml schedule | Done |
| SUM: update delivery | Tagged releases with SBOM attached | | Planned |
| Security guidelines (SG) | Procedures for scans, findings, rules, mappings and credential rotation | docs/procedures/ | Done |
| SG: hardening guidance | Container hardening subset with before and after counts | docs/hardening.md | Done |

## Gaps
- No second reviewer. Changes are self-reviewed, which is weaker than an independent review.
- No signed releases. Planned with the first tagged release.
- Penetration testing of the scanner itself is out of scope.
