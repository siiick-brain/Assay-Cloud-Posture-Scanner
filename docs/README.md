# Documentation index

Start with repo-map.md and contracts.md if you want to change code. Start with procedures/run-a-scan.md if you want to use the scanner.

## Planning
| File | What it holds |
|---|---|
| [spec.md](spec.md) | Item list 0 to 18 and the 24 quality gates |
| [repo-map.md](repo-map.md) | One line per module with its public entry points |
| [STYLE.md](STYLE.md) | Writing rules for code comments, docs and commits |
| [GLOSSARY.md](GLOSSARY.md) | Terms used across the docs |
| [skills-evidence.md](skills-evidence.md) | Proof row for every skill claim |

## Design
| File | What it holds |
|---|---|
| [requirements.md](requirements.md) | Functional, security and quality requirements with verification methods |
| [architecture.md](architecture.md) | Module diagram and flow |
| [contracts.md](contracts.md) | Frozen resource, finding and rule contracts |
| [threat-model.md](threat-model.md) | STRIDE table and credential theft attack tree |
| [adr/](adr/) | Architecture decision records |
| [diagrams/](diagrams/) | Mermaid sources: architecture, data flow and finding lifecycle |

## Security and process
| File | What it holds |
|---|---|
| [risk-assessment.md](risk-assessment.md) | The scanner's own risks, likelihood times impact |
| [sdl-checklist.md](sdl-checklist.md) | Secure development checklist informed by IEC 62443-4-1 |
| [cra-annex1-map.md](cra-annex1-map.md) | CRA Annex I self-assessment, no conformity claim |
| [hardening.md](hardening.md) | OpenSCAP scan of an Ubuntu 24.04 container, before and after counts |

## Procedures
| File | Use it when |
|---|---|
| [procedures/run-a-scan.md](procedures/run-a-scan.md) | Running an emulator, fixture, live or OpenSCAP scan |
| [procedures/handle-a-finding.md](procedures/handle-a-finding.md) | Triaging and closing a finding |
| [procedures/add-a-rule.md](procedures/add-a-rule.md) | Adding a rule |
| [procedures/add-a-framework-mapping.md](procedures/add-a-framework-mapping.md) | Mapping a rule to a framework control |
| [procedures/rotate-scanner-credentials.md](procedures/rotate-scanner-credentials.md) | Rotating or revoking live mode credentials |

## Feature docs
| File | What it holds |
|---|---|
| [rules.md](rules.md) | Rule catalog, generated from rules/ |
| [scoring.md](scoring.md) | Score formula and worked table |
| [iam-review.md](iam-review.md) | Least-privilege review with a before and after example |
| [tool-comparison.md](tool-comparison.md) | Trivy, Checkov and Prowler against the testbed |
| [cspm-cnapp.md](cspm-cnapp.md) | What CSPM and CNAPP cover and what this scanner covers |
| [evaluation.md](evaluation.md) | Measured results for every quality gate |

## Repository
| File | What it holds |
|---|---|
| [repo-metadata.md](repo-metadata.md) | Proposed GitHub description, topics and social preview |
| [../CHANGELOG.md](../CHANGELOG.md) | Changes per release |
| [../SECURITY.md](../SECURITY.md) | How to report a vulnerability |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Setup and commit rules |

## CI
Workflows live in .github/workflows. ci.yml runs lint, types, tests with the 85 percent gate, the emulator job, the allowlist static check and the style and authorship check. security.yml runs Trivy, gitleaks and Syft. regression.yml runs the weekly testbed oracle.
