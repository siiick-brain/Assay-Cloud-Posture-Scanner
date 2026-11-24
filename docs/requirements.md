# Security and functional requirements

Each requirement has an ID, the item that delivers it and a verification method: T (automated test), I (inspection), D (demo with recorded output) or A (analysis). scripts/trace.ps1 lists every ID with the files that reference it.

## Functional

| ID | Requirement | Item | Method |
|---|---|---|---|
| REQ-F-001 | Collect S3, EC2, RDS, IAM, CloudTrail, KMS, Secrets Manager and ACM configuration through boto3. | 3 | T |
| REQ-F-002 | Collect Azure storage, NSG, Key Vault and disk configuration through the same collector interface. | 3 | T |
| REQ-F-003 | Read Terraform plan JSON into the resource model. | 3 | T |
| REQ-F-004 | Normalize every resource to id, type, provider, region, config and tags. | 3 | T |
| REQ-F-005 | Ship at least 25 rules with stable IDs, a positive and a negative test each. | 4 | T |
| REQ-F-006 | Score each finding 0 to 10 from base severity, exposure, asset criticality and data sensitivity. | 5 | T |
| REQ-F-007 | Write JSON, SARIF, Markdown and offline HTML reports with a SHA-256 manifest. | 6 | T |
| REQ-F-008 | Map every rule to at least three of the seven frameworks and generate a coverage report. | 7 | T |
| REQ-F-009 | Ingest Trivy, Prowler and Checkov JSON with a source label and deduplication. | 8 | T |
| REQ-F-010 | Propose a least-privilege IAM policy from a workload requirement file and show the diff. | 9 | T |
| REQ-F-011 | Check certificate expiry, weak keys and signatures, key rotation, secret age and TLS endpoint settings. | 10 | T |
| REQ-F-012 | Record OpenSCAP before and after counts for an Ubuntu 24.04 container. | 11 | D |
| REQ-F-013 | Track each finding through new, open, assigned, fixed_claimed, verified_closed and reopened. | 12 | T |
| REQ-F-014 | Close a finding as verified only after a rescan in emulator or fixture mode. | 12 | T |
| REQ-F-015 | Provide scan, report, diff, trend, iam-review, tls-check and map-coverage commands. | 13 | T |

## Security

| ID | Requirement | Item | Method |
|---|---|---|---|
| REQ-S-001 | Block every AWS operation not in cspm/live/allowlist.yaml before it is sent. | 3 | T |
| REQ-S-002 | Fail CI when code calls an AWS operation that is not on the allowlist. | 15 | T |
| REQ-S-003 | Refuse non-emulator endpoints in testbed mode. | 3 | T |
| REQ-S-004 | Run live mode only with --live and CSPM_ALLOW_LIVE=1. | 13 | T |
| REQ-S-005 | Read credentials only from environment variables and never write them to disk or logs. | 3 | T |
| REQ-S-006 | Redact secret-like values, account IDs and ARNs in evidence before storage or report. | 6 | T |
| REQ-S-007 | Make no network calls by default. | 13 | T |
| REQ-S-008 | Run the container as non-root with a read-only root filesystem. | 13 | I |
| REQ-S-009 | Pin dependencies by hash and actions by full commit SHA. | 15 | I |
| REQ-S-010 | Keep private/ and artifacts/ out of git and free of secrets per gitleaks. | 0 | T |
| REQ-S-011 | Never call secretsmanager:GetSecretValue, s3:GetObject or kms:Decrypt. | 3 | T |

## Quality

| ID | Requirement | Item | Method |
|---|---|---|---|
| REQ-Q-001 | Recall 100 percent on the seeded ground truth. | 14 | T |
| REQ-Q-002 | Zero findings on the secure testbed. | 14 | T |
| REQ-Q-003 | Full testbed scan under 60 seconds. | 14 | T |
| REQ-Q-004 | Coverage at least 85 percent, ruff and mypy strict clean. | 14 | T |
| REQ-Q-005 | Reports validate against cspm/contracts/findings.schema.json. | 6 | T |
| REQ-Q-006 | Docs, comments and commits pass scripts/check-style.ps1. | 0 | T |
