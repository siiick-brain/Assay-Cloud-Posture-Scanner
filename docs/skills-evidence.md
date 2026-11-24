# Skills evidence

Each skill claimed for this project points to a file or test in this repo. scripts/verify-skills.ps1 checks that every proof path exists. A row without proof would stay Planned or Not verified.

| Skill | Item | Proof | Status |
|---|---|---|---|
| Python with boto3 | 3 | cspm/collectors/aws.py; tests/unit/test_collectors_aws.py | Verified (Moto) |
| Azure SDK | 3 | cspm/collectors/azure.py; tests/unit/test_collectors_azure.py | Partly verified: fixture path tested, live SDK path Not verified |
| Prowler | 8 | fixtures/recorded/prowler/; docs/tool-comparison.md | Verified (iac provider only) |
| Trivy | 8 | fixtures/recorded/trivy/; docs/tool-comparison.md | Verified |
| CSPM and CNAPP concepts | 8 | docs/cspm-cnapp.md | Verified |
| Misconfiguration detection (public storage, open rules, encryption, IAM) | 4 | rules/; tests/unit/test_rules_cases.py; tests/integration/test_recall.py | Verified |
| Severity scoring | 5 | cspm/scoring/__init__.py; tests/unit/test_scoring.py; docs/scoring.md | Verified |
| Evidence reporting | 6 | cspm/reports/; tests/unit/test_reports.py; docs/reports.md | Verified |
| Control mapping to seven frameworks | 7 | mappings/; tests/unit/test_mapping.py; docs/mapping-coverage.md | Verified (identifiers, informed by, no compliance claim) |
| Security requirements documents | 1 | docs/requirements.md; scripts/trace.ps1 | Verified |
| Threat modelling | 1 | docs/threat-model.md | Verified |
| OpenSCAP and CIS-aligned Ubuntu hardening | 11 | docs/hardening.md; scripts/openscap/; cspm/ingest/xccdf.py | Verified (container scan, no compliance claim) |
| Least-privilege IAM review | 9 | cspm/iam/; docs/iam-review.md; examples/iam/ | Verified |
| Certificate and key management checks | 10 | cspm/tls/; docs/tls-checks.md | Verified |
| Remediation tracking and rescanning | 12 | cspm/store/; docs/demo/remediation-demo.md | Verified (Moto) |
| CI/CD security | 15 | .github/workflows/; scripts/check_allowlist.py | Verified: ci and security workflows pass on GitHub Actions. The weekly regression workflow has not fired yet |
| Terraform | 2 | testbed/insecure/; testbed/secure/ | Verified (applied to Moto) |
| Docker hardening of the scanner image | 13 | Dockerfile; docs/usage.md | Verified (non-root, read-only root filesystem run) |
