# Tool comparison (Item 8)

All numbers come from the recorded runs in `fixtures/recorded/` (Trivy 0.76.2, Checkov 3.4.7, Prowler 5.52.0; sample runs on 2026-11-23, testbed and image runs on 2026-11-24). `tests/unit/test_ingest_prowler_compare.py` and `tests/unit/test_ingest_testbed_compare.py` recompute the tables from those files, so a change in the parsers or the mapping that moves a number fails the build.

## Terraform scanners cannot see runtime state

Trivy config, Checkov and Prowler iac read Terraform source. They never see the account that the code produced. On the testbed that hides five of the 16 seeded AWS issues from all three tools:

- Access key age (ASSAY-IAM-005): the key's creation date exists only once the key exists. The Terraform has an `aws_iam_access_key` block and nothing more.
- MFA devices (ASSAY-IAM-004): the code creates a console password; whether an MFA device was enrolled later is account state.
- Account defaults left unset (ASSAY-EC2-006 EBS encryption by default, ASSAY-IAM-008 password policy, ASSAY-LOG-001 CloudTrail): these are seeded by omission. A scanner of source code cannot report a resource that was never written, and a real account may have them set outside this code anyway.

assay-cspm scans collector output from the emulator, so it sees all five. The reverse also holds: the IaC tools flag problems before anything is deployed.

## What was scanned

Two targets. The testbed (`testbed/insecure` and `testbed/secure`) with the 16 AWS entries of `testbed/ground-truth.yaml`, restated by Terraform address in `fixtures/recorded/testbed-ground-truth-tf.yaml`. Three entries have no Terraform resource and get an `account:` key. The log target bucket `aws_s3_bucket.logs` is meant to pass every assay rule, so a finding on it counts as a false positive. So does every finding on the secure stack, which must give zero.

Before the testbed existed, the IaC column used `fixtures/recorded/trivy/sample-tf/main.tf`: 14 seeded issues on 7 resources plus 2 resources meant to be clean (`aws_s3_bucket.private_logs`, `aws_kms_key.good`). The seeded list is `fixtures/recorded/sample-ground-truth.yaml`, written from the sample's design. That table stays below for the record.

## Method

- Each tool's JSON goes through `cspm.ingest.ingest`, so every finding carries the tool as `source`.
- A tool finding detects a seeded issue when its check id maps to that assay rule in `cspm.ingest.ASSAY_EQUIVALENT` and its normalized resource matches (see matching key below).
- A finding that matches no seeded issue and sits on a resource meant to be clean counts as a false positive against this ground truth.
- A finding that matches no seeded issue and sits on an insecure resource counts as "beyond the seed": a real weakness the sample did not plan for (backup retention, deletion protection and so on). These are not false positives.

## Results on the testbed

assay-cspm ran its engine on `testbed/recorded/insecure-aws.json` and `secure-aws.json` (collector output from Moto) with the scan clock at 2027-03-23, as in `tests/integration/test_recall.py`. Its findings use ARNs, so they are matched to the ground truth by rule, type and resource name with the matcher from that test.

| | Trivy config | Checkov | Prowler iac | assay-cspm |
|---|---|---|---|---|
| Findings on insecure after ingest | 17 | 39 | 17 | 16 |
| Seeded AWS issues found (of 16) | 9 | 9 | 9 | 16 |
| Seeded issues missed | 7 | 7 | 7 | 0 |
| False positives on `aws_s3_bucket.logs` | 0 | 4 | 0 | 0 |
| Findings on the secure stack (false positives against this ground truth) | 5 | 19 | 5 | 0 |
| Real findings beyond the seed | 5 | 21 | 5 | 0 |
| Seeded issues only this tool found, among the three tools | 0 | 2 (S3-003, IAM-001) | 0 | not counted |
| Seeded issues only this tool found, all four | 0 | 0 | 0 | 5 (EC2-006, IAM-004, IAM-005, IAM-008, LOG-001) |

Misses per tool, beyond the five runtime-only issues above:

- Trivy and Prowler iac: S3-003 and IAM-001, the same two as on the sample. AWS-0088 does not fire on a bucket without an encryption block (AWS-0132, customer managed key, does and is not mapped). AWS-0057 does not fire on `Action = "*"` built with `jsonencode`.
- Checkov: EC2-003 and IAM-002. Checkov has port checks for 22, 3389 and 80 and an all-ports check, but none for 5432. For the `s3:*` policy it fires CKV_AWS_288, 289, 290 and 355, which are about unconstrained resources rather than the service wildcard, so they count as beyond the seed. CKV_AWS_63 checks only a bare `*`.

Overlap among the three tools: 7 seeded issues found by all three (S3-001, S3-002, S3-004, S3-005, EC2-001, EC2-005, KMS-001), 2 by Trivy and Prowler only (EC2-003, IAM-002), 2 by Checkov only (S3-003, IAM-001). assay-cspm found all 11 of those plus the 5 runtime-only issues.

False positives:

- Checkov on `aws_s3_bucket.logs`: CKV2_AWS_61 (lifecycle), CKV2_AWS_62 (event notifications), CKV_AWS_144 (cross-region replication) and CKV_AWS_145 (KMS instead of SSE-S3). The same four checks give 11 of the 19 secure-stack findings. The other 8 are VPC flow logs and default security group (CKV2_AWS_11, 12), an unattached security group (CKV2_AWS_5), CloudTrail extras (CKV2_AWS_10, CKV_AWS_252, CKV_AWS_35), a KMS key policy (CKV2_AWS_64) and IAM users instead of SSO (CKV_AWS_273).
- Trivy and Prowler on the secure stack: CloudTrail with a customer managed key and CloudWatch delivery (AWS-0015, AWS-0162), MFA enforcement on a group (AWS-0123), a customer managed key on the trail bucket (AWS-0132) and VPC flow logs (AWS-0178). All are hardening advice outside assay's rules, not misconfigurations of the seeded kind.

Checkov comes closest on the console user: CKV2_AWS_22 (user has console access) and CKV_AWS_273 fire on `aws_iam_user.dev`. Neither looks at MFA, so neither is mapped to IAM-004.

Mapping changes made with this run: AWS-0345 (unrestricted `s3:*` policy) now maps to ASSAY-IAM-002. CKV_AWS_260 was mapped to ASSAY-EC2-003, but that check is port 80, not a database port, so the mapping was removed. Neither change moves a sample number.

Prowler iac again reports the same check ids on the same resources as `trivy config`, on both stacks.

## Results on the sample Terraform

assay-cspm is not in this table: it reads collector output or a Terraform plan, and the sample has neither.

| | Trivy config | Checkov | Prowler iac |
|---|---|---|---|
| Findings after ingest | 23 | 44 | 23 |
| Seeded issues found (of 14) | 12 | 14 | 12 |
| Seeded issues missed | IAM-001, S3-003 | none | IAM-001, S3-003 |
| False positives on clean resources | 0 | 4 | 0 |
| Real findings beyond the seed | 8 | 21 | 8 |
| Seeded issues only this tool found | 0 | 2 (IAM-001, S3-003) | 0 |

Trivy reports 24 rows; two AWS-0107 rows for the same security group (one per offending ingress block) merge into one finding with both line numbers.

Overlap: all three tools found the same 12 seeded issues (S3-001, S3-002, S3-004, S3-005, EC2-001, EC2-002, EC2-005, RDS-001, RDS-002, KMS-001, LOG-001, LOG-002). Checkov alone found the other two.

Misses:

- S3-003 (no default encryption): Trivy has no failing check for it. The only encryption hit is AWS-0132 (use a customer managed key), which also fires on buckets with SSE-S3, so it is not mapped to S3-003. AWS has applied SSE-S3 to new buckets by default since January 2023, which is the likely reason. Checkov flags CKV_AWS_145.
- IAM-001 (`Action = "*"` on `Resource = "*"` in an `aws_iam_policy` built with `jsonencode`): no Trivy failure on that resource. The cause was not investigated. Checkov flags it eight ways (CKV_AWS_62, 63, 286, 287, 288, 289, 290, 355 plus CKV2_AWS_40).

False positives (Checkov, all on clean resources and all hardening advice rather than misconfiguration):

| Check | Resource | Why it is not a seeded issue |
|---|---|---|
| CKV2_AWS_62 | aws_s3_bucket.private_logs | event notifications are optional |
| CKV2_AWS_61 | aws_s3_bucket.private_logs | a lifecycle rule is a cost choice |
| CKV_AWS_144 | aws_s3_bucket.private_logs | cross-region replication is a resilience choice |
| CKV2_AWS_64 | aws_kms_key.good | without a policy block the AWS default key policy applies |

Severity: Checkov leaves `severity` empty without a Prowler/Bridgecrew platform key, so every Checkov finding ingests as medium. Trivy and Prowler give their own severity.

Prowler `iac` runs Trivy inside. Its 24 failures are the same check ids on the same resources as `trivy config`, so it adds a second output format, not a second opinion.

## Other recorded runs

| Run | Count | Notes |
|---|---|---|
| `trivy fs` on the integration branch (2026-11-24) | 5 Dockerfile misconfigurations, 66 Terraform rows, 0 vulnerabilities in uv.lock, 0 secrets | DS-0026 (no HEALTHCHECK) on all three Dockerfiles, DS-0002 (root user) on the OpenSCAP and target images; the scanner image sets a non-root user. The Terraform rows are the sample (24), each testbed stack (17 and 5) and a root module `main.tf` (20) that Trivy assembled from both stacks together |
| `trivy fs` on this repo (2026-11-23) | 23 misconfigurations (the sample), 0 vulnerabilities in uv.lock, 4 secret findings | All 4 secret findings (5 raw rows) are false positives: synthetic tokens from the redaction tests that pytest wrote to the gitignored `.pytest_cache` |
| `trivy image assay-cspm:dev` (root Dockerfile, 2026-11-24) | 258 (252 Debian packages, 6 pip) | 54 high, 106 medium, 82 low, 16 unknown (ingested as info). 36 have a fixed version, 0 secrets. Identical to the base image: the hash-pinned project dependencies add no vulnerability. The 6 Python findings are in pip 25.0.1 from the base image |
| `trivy image` python:3.12-slim by digest | 258 (252 Debian packages, 6 Python packages) | 54 high, 106 medium, 82 low, 16 unknown (ingested as info). 36 have a fixed version. |
| Prowler `kubernetes` | Not verified | No project cluster. The default kubeconfig context was a local kind cluster this project did not create; that output was not recorded |

## Matching key for dedupe

`cspm.ingest.dedupe(tool_findings, assay_findings)` drops a tool finding when it shares a key with an assay finding. The key is `(resource key, assay rule id)`:

- Resource key: the resource id in lower case with any `module.x.` prefix and trailing `[index]` removed. Terraform bucket sub-resources (`aws_s3_bucket_acl.x`, `aws_s3_bucket_versioning.x` and so on) fold onto `aws_s3_bucket.x`. That last step assumes the common convention of naming the sub-resource after its bucket.
- Assay rule id: assay findings use their own rule id. Tool findings use every rule listed for their check id in `ASSAY_EQUIVALENT`; a check with no entry never dedupes. AWS-0107 (SSH or RDP open) maps to EC2-001, EC2-002 and EC2-003 because one Trivy check covers all three.

Assay findings from a Terraform plan use the Terraform address as `resource_id` (docs/contracts.md), so the key lines up with Trivy, Checkov and Prowler IaC output. Findings from a live or emulator scan use ARNs and will only dedupe against tools that also report ARNs, such as Prowler's AWS provider.
