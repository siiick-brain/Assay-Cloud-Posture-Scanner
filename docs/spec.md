# ASSAY SPEC (assay-cspm)

The item list for this project, written before the code. Decisions taken here are recorded in docs/adr/0000-spec-decisions.md.

## Scope

assay-cspm is a Python cloud security posture scanner. It collects resource configuration from AWS (boto3) and Azure (Azure SDK, fixtures in tests), normalizes it, runs rules for public storage, open network rules, encryption, IAM, logging and key management, scores each finding, writes evidence reports, maps rules to seven frameworks, ingests Trivy, Prowler and Checkov output, reviews IAM policies for least privilege, checks certificates and keys, hardens an Ubuntu container with OpenSCAP and tracks remediation through rescans.

AWS is the primary target. Azure is a second provider with the same collector interface, tested from synthetic fixtures only. Tests and CI never touch a real account.

Frameworks (informed by, no compliance claim): CIS AWS Foundations Benchmark, NIST SP 800-53 Rev. 5 with NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, SOC 2 Trust Services Criteria (2017, revised points of focus 2022), NIS2 Directive Article 21(2), IEC 62443-4-1 practices, EU Cyber Resilience Act Annex I.

Stack: Python 3.12, uv with a hashed lockfile, pytest, Hypothesis, ruff, mypy strict, Moto as the emulator, Terraform for the testbed, Docker.

## Items

Each item lists its Done when test. Thresholds are in the Quality gates section.

### Item 0. Repository foundation
Git repo, .gitignore covering private/ and artifacts/, commit hooks (author email, title under 72 chars, imperative title, no trailers, banned words, no em dash), docs/STYLE.md, docs/GLOSSARY.md, docs/skills-evidence.md, scripts/check-style.ps1 with a bad and a good fixture, standard repo files, private/plan.md.
Done when: the hook rejects a trailer, a wrong email and a bad title on a throwaway branch and the style fixtures behave.

### Item 1. Requirements and design
docs/requirements.md with IDs and verification methods, docs/threat-model.md (STRIDE plus a credential theft attack tree), Mermaid architecture diagram, ADRs for resource model, rule engine, emulator and read-only enforcement, scripts/trace.ps1. Frozen contracts: resource model, findings schema, rule interface and rule ID list, allowlist, finding model.
Done when: trace.ps1 lists every requirement and the contracts-v1 tag exists.

### Item 2. Testbed
Terraform stacks testbed/insecure and testbed/secure for the Moto server, Azure synthetic fixtures, testbed/ground-truth.yaml and a validation test.
Done when: the insecure stack applies to the emulator and the ground truth validates.

### Item 3. Collectors and resource model
Typed resource model code, collectors for AWS (emulator plus allowlist hook), Azure (fixtures, live SDK path Not verified) and Terraform plan JSON. Credentials from environment only. Testbed mode refuses non-emulator endpoints.
Done when: collectors return the expected testbed resources and the write-block and endpoint-refusal tests pass.

### Item 4. Rules
At least 25 rules using the frozen IDs, each with severity base, rationale, remediation and positive and negative fixtures. docs/rules.md generated from code.
Done when: every rule test passes, recall on the ground truth is 100 percent and the secure testbed gives zero findings.

### Item 5. Scoring
Score 0 to 10 and a band from base severity, exposure, asset criticality tag and data sensitivity tag. docs/scoring.md with a worked table. Hypothesis tests for bounds and exposure monotonicity.
Done when: scoring tests pass.

### Item 6. Reports and evidence
JSON, SARIF 2.1.0, Markdown and single-file offline HTML with filters. Evidence redacted before storage. SHA-256 manifest per report set. Schema validation.
Done when: reports validate and the HTML opens offline.

### Item 7. Control mapping
mappings/*.yaml for the seven frameworks, identifiers only, one-line rationale per mapping in our own words, local identifier lists and a coverage report generator.
Done when: every rule maps to at least three frameworks, every identifier exists in the local list and the coverage report generates.

### Item 8. Tool ingestion and comparison
Ingest Trivy, Prowler and optional Checkov JSON into the finding model with a source label and deduplication. Real recorded outputs only. docs/tool-comparison.md and docs/cspm-cnapp.md.
Done when: ingestion tests pass on recorded outputs and the comparison table comes from real runs.

### Item 9. IAM least-privilege review
cspm iam-review: wildcard and privilege escalation pattern detection, comparison with a declared workload requirement file, proposed policy and diff. docs/iam-review.md.
Done when: the proposed example policy passes the project's own IAM rules.

### Item 10. Certificate and key management checks
Certificate expiry windows, weak keys and signatures, KMS rotation, secret age, TLS endpoint checker tested against local weak and strong servers.
Done when: TLS and certificate tests pass.

### Item 11. OpenSCAP hardening
openscap-scanner plus SCAP Security Guide for Ubuntu 24.04 in a container, before scan, documented hardening subset, after scan, XCCDF ingestion, list of rules not applicable in containers.
Done when: before and after counts come from real runs.

### Item 12. Remediation tracking
SQLite store with finding lifecycle, owner, history, SLA due dates by severity, rescan verification, cspm diff and cspm trend, recorded fix-and-rescan demo with one regression.
Done when: the demo output is recorded and store tests pass.

### Item 13. CLI and packaging
Commands scan, report, diff, trend, iam-review, tls-check, map-coverage. No network by default. Hash-pinned dependencies. Non-root Docker image with read-only root filesystem.
Done when: CLI tests pass and the image scans the emulator.

### Item 14. Evaluation
Unit, property and integration tests, coverage gate, ruff, mypy strict, docs/evaluation.md with recall, false positives and Met or Missed per threshold.

### Item 15. CI/CD
Workflows for lint, types, tests with coverage gate, emulator integration, Trivy, gitleaks, Syft SBOM, style and authorship, allowlist static check, scheduled regression scan. Actions pinned by SHA with least-privilege permissions. actionlint clean.

### Item 16. Documentation
docs/procedures/ (add a rule, add a framework mapping, run a scan, handle a finding, rotate scanner credentials), docs/risk-assessment.md, docs/sdl-checklist.md, docs/cra-annex1-map.md (self-assessment only), docs/README.md, CHANGELOG.md, docs/repo-metadata.md, docs/diagrams/.

### Item 17. Visuals and README
Terminal renders, browser captures of the HTML report, charts and a GIF under 5 MB from real output. Private details blurred and checked by OCR. scripts/check-readme-images.ps1. README in this order: summary, demo, features, quick start, architecture, rules, evaluation results, framework mapping, limits, security, licence.

### Item 18. Skills verification and publish
scripts/verify-skills.ps1 -Strict, artifacts/skills-report.md, docs/skills-evidence.md with proof rows, the 24 gates below, security audit record, artifacts/scorecard.md, private/publish-checklist.md, private/linkedin.md.

## Quality gates (the 24 gate rows for Item 18)

| Gate | Check | Threshold |
|---|---|---|
| G01 | ruff | 0 errors |
| G02 | mypy strict on cspm/ and rules/ | 0 errors |
| G03 | pytest | all pass |
| G04 | coverage | at least 85 percent |
| G05 | rule count | at least 25 |
| G06 | positive and negative test per rule | every rule |
| G07 | recall on seeded ground truth | 100 percent |
| G08 | findings on secure testbed | 0 |
| G09 | insecure testbed finding count | equals ground truth count |
| G10 | full testbed scan time | under 60 seconds |
| G11 | reports validate against schema | all formats |
| G12 | framework mappings per rule | at least 3 of 7 |
| G13 | mapped identifiers exist in local lists | 100 percent |
| G14 | allowlist write block test | passes |
| G15 | static allowlist check | no unlisted operation |
| G16 | gitleaks on repo, private/ and artifacts/ | 0 leaks |
| G17 | style check on docs, comments and commits | passes |
| G18 | actions pinned by SHA | every action |
| G19 | actionlint | 0 errors |
| G20 | Trivy and Prowler outputs recorded from real runs | present or Not verified with cause |
| G21 | OpenSCAP before and after counts from real runs | present or Not verified with cause |
| G22 | demo fix and rescan recorded with one regression | present |
| G23 | README images pass the image check | passes |
| G24 | every skill claim has a proof row | 100 percent |

## Rule ID list

Frozen at contracts-v1. The machine-readable copy is cspm/contracts/rule_ids.py.
