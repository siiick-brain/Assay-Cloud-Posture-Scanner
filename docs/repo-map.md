# Repo map

One line per module: purpose and public entry points. Update when a module changes.

| Module | Purpose | Public |
|---|---|---|
| cspm/contracts/resource.py | Normalized resource model (frozen) | Provider, Resource |
| cspm/contracts/finding.py | Finding model and lifecycle enums (frozen) | Finding, Severity, FindingState, VerificationStatus, Source, ScanMode, ControlRef, verification_for |
| cspm/contracts/rule.py | Rule protocol and scan context (frozen) | Rule, RuleMeta, ScanContext, Violation |
| cspm/contracts/rule_ids.py | Rule IDs, resource types, exposure levels (frozen) | RULE_IDS, RULE_ID_SET, RESOURCE_TYPES, EXPOSURE_LEVELS |
| cspm/contracts/findings.schema.json | Findings report JSON schema 1.0.0 (frozen) | |
| cspm/live/allowlist.yaml | Read-only AWS operation list (frozen) | |
| cspm/collectors | AWS (guarded boto3), Azure (synthetic fixtures, live SDK Not verified) and Terraform plan collectors | collect |
| cspm/cli | command line (scan, report, diff, trend, iam-review, tls-check, map-coverage) | main |
| cspm/engine | runs rules by resource type, merges violations, scores and maps findings | run_rules, build_finding |
| cspm/scoring | 0 to 10 score and band from severity, exposure and tags (docs/scoring.md) | score, score_parts, band_for |
| rules/ | 33 rule classes and the registry by rule ID and resource type | ALL_RULES, RULES_BY_ID, RULES_BY_TYPE, rules_for_type |
| scripts/gen_rules_doc.py | writes docs/rules.md from rule metadata | main, render |
| cspm/reports | JSON, SARIF 2.1.0, Markdown, offline HTML, SHA-256 manifest, redaction (docs/reports.md) | write_reports, build_report, finding_to_dict, finding_from_dict, validate_report, verify_manifest, Redactor, redact |
| cspm/store | SQLite lifecycle store, SLA, history, diff, trend, fix-and-rescan demo (docs/remediation.md) | Store, ScanMeta, ScanDiff, FindingDelta, TrendPoint, SLA_DAYS, due_date_for, demo.run_demo |
| cspm/mapping | loads mappings/*.yaml, validates identifiers, writes docs/mapping-coverage.md | controls_for, validate, write_coverage, main |
| mappings/ | rule to control YAML per framework and local identifier lists | |
| cspm/ingest | Trivy, Prowler, Checkov ingestion, OpenSCAP via xccdf.py, dedupe, comparison (docs/tool-comparison.md) | ingest, dedupe, match_key, ASSAY_EQUIVALENT, compare.score_tool |
| cspm/ingest/xccdf.py | OpenSCAP XCCDF 1.2 results to findings (source openscap) | parse_xccdf, count_results |
| cspm/iam | least-privilege review, escalation patterns, proposal and diff | review, find_issues, policy_diff, main_iam_review, PATTERNS |
| cspm/tls | TLS endpoint, certificate, KMS rotation and secret age checks | check_endpoint, scan_endpoint, check_certificate, check_certificate_file, check_kms_rotation, check_secret_age, main_tls_check |
| scripts/demo_remediation.py | fix-and-rescan demo runner | |
| fixtures/recorded/ | redacted real Trivy, Checkov and Prowler output | |
| cspm/collectors/guard.py | allowlist before-call hook, emulator host check, live gate | enforce_allowlist, check_emulator_endpoint, check_live_allowed |
| testbed/ | Moto Terraform stacks, Azure fixtures, ground truth, recorded scans, plan JSON | apply.sh |
| Dockerfile | hash-pinned, non-root, read-only image | |
| scripts/check-style.ps1 | Writing rule checker | |
| scripts/trace.ps1 | Requirement trace table | |
| scripts/visuals/ | Item 17: terminal render, report capture, charts and demo GIF for docs/images | term_render.render, demo_gif.build |
| scripts/check-readme-images.ps1 | Item 17: image references, sizes and OCR check for private strings | |
| .githooks/ | commit-msg and pre-commit hooks | |
| scripts/check_allowlist.py | static check that boto3 calls in cspm/ are on the allowlist | main, check, find_calls |
| scripts/openscap/ | run.sh (build, scan, harden, rescan), harden.sh, summarize.py | |
| docker/ | OpenSCAP scanner and Ubuntu 24.04 target images, compose for Moto | |
| .github/workflows | ci.yml, security.yml, regression.yml | |
