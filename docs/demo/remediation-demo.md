# Fix-and-rescan demo (Item 12)

Recorded on 2026-11-24 against Moto 5.2.6 in Docker (host port 5010) with Terraform 1.17.2 and AWS provider 4.67.0. Every block below is real terminal output from that run. Terraform output is cut to its summary line; the full logs are in `artifacts/demo/logs/`. Moto's account 123456789012 is synthetic. Local paths are trimmed to paths relative to `artifacts/demo/`.

## How it ran

1. Copied `testbed/insecure` into `artifacts/demo/tf/` (ignored) and pointed the provider endpoints at `http://localhost:5010`. `testbed/` was not changed.
2. Applied the insecure stack and scanned it with the real CLI. Then fixed the stack in five Terraform steps and rescanned after each one. The scanner stayed read-only; only Terraform wrote to Moto.
3. Added one regression: re-opened SSH to `0.0.0.0/0` on the security group after its fix was verified, rescanned, then removed the rule again and rescanned.
4. Recorded the eight findings reports in order into a SQLite store with `scripts/demo_remediation.py --claim-absent`, which marks a finding `fixed_claimed` before the rescan that should close it, as an operator would.
5. Ran `cspm diff` and `cspm trend` on that store.

| Step | Scan ID | Terraform change | Findings |
|---|---|---|---|
| 0 | s0-baseline | insecure stack as seeded | 16 |
| 1 | s1-s3-public | public bucket ACL to `private`, Block Public Access on | 14 |
| 2 | s2-s3-hygiene | default encryption, versioning and access logging on the unencrypted bucket | 11 |
| 3 | s3-network-ebs | SSH rule removed and PostgreSQL limited to the VPC CIDR, volume encrypted with the stack key, EBS encryption by default on | 7 |
| 4 | s4-iam | wildcard policies scoped down, console login and access key removed from the user, strict password policy | 2 |
| 5 | s5-kms-trail | key rotation on, multi-region CloudTrail trail with its own hardened bucket | 0 |
| 6 | s6-regression-ssh | SSH from `0.0.0.0/0` added back | 1 |
| 7 | s7-ssh-refixed | SSH rule removed again | 0 |

The IAM user fix removes console access instead of enrolling MFA, since a virtual MFA device needs live TOTP codes that Terraform cannot supply. Encrypting the volume replaces it, so ASSAY-EC2-005 closes because the unencrypted volume is gone.

A first attempt at step 3 set `encrypted = true` without `kms_key_id`. Moto then created a key for the volume and reported it as a customer managed key without rotation, so the scan showed 8 findings with a new ASSAY-KMS-001. Real AWS would use the AWS managed `aws/ebs` key. The run was reset and replayed from step 0 with the volume pinned to the stack key. That attempt is kept in `artifacts/demo/attempt1/`.

## Scans

```text
$ terraform apply   # s0-baseline
Apply complete! Resources: 25 added, 0 changed, 0 destroyed.
$ cspm scan --provider aws --mode emulator --endpoint http://localhost:5010 --now +120d --scan-id s0-baseline --out scans/s0-baseline
collected 14 resources -> scans\s0-baseline\resources.json
16 findings -> scans\s0-baseline\findings.json
$ terraform apply   # s1-s3-public
Apply complete! Resources: 1 added, 1 changed, 0 destroyed.
$ cspm scan --provider aws --mode emulator --endpoint http://localhost:5010 --now +120d --scan-id s1-s3-public --out scans/s1-s3-public
collected 14 resources -> scans\s1-s3-public\resources.json
14 findings -> scans\s1-s3-public\findings.json
$ terraform apply   # s2-s3-hygiene
Apply complete! Resources: 3 added, 0 changed, 0 destroyed.
$ cspm scan --provider aws --mode emulator --endpoint http://localhost:5010 --now +120d --scan-id s2-s3-hygiene --out scans/s2-s3-hygiene
collected 14 resources -> scans\s2-s3-hygiene\resources.json
11 findings -> scans\s2-s3-hygiene\findings.json
$ terraform apply   # s3-network-ebs
Apply complete! Resources: 2 added, 1 changed, 1 destroyed.
$ cspm scan --provider aws --mode emulator --endpoint http://localhost:5010 --now +120d --scan-id s3-network-ebs --out scans/s3-network-ebs
collected 14 resources -> scans\s3-network-ebs\resources.json
7 findings -> scans\s3-network-ebs\findings.json
$ terraform apply   # s4-iam
Apply complete! Resources: 1 added, 2 changed, 2 destroyed.
$ cspm scan --provider aws --mode emulator --endpoint http://localhost:5010 --now +120d --scan-id s4-iam --out scans/s4-iam
collected 14 resources -> scans\s4-iam\resources.json
2 findings -> scans\s4-iam\findings.json
$ terraform apply   # s5-kms-trail
Apply complete! Resources: 7 added, 1 changed, 0 destroyed.
$ cspm scan --provider aws --mode emulator --endpoint http://localhost:5010 --now +120d --scan-id s5-kms-trail --out scans/s5-kms-trail
collected 16 resources -> scans\s5-kms-trail\resources.json
0 findings -> scans\s5-kms-trail\findings.json
$ terraform apply   # s6-regression-ssh
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.
$ cspm scan --provider aws --mode emulator --endpoint http://localhost:5010 --now +120d --scan-id s6-regression-ssh --out scans/s6-regression-ssh
collected 16 resources -> scans\s6-regression-ssh\resources.json
1 findings -> scans\s6-regression-ssh\findings.json
$ terraform apply   # s7-ssh-refixed
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.
$ cspm scan --provider aws --mode emulator --endpoint http://localhost:5010 --now +120d --scan-id s7-ssh-refixed --out scans/s7-ssh-refixed
collected 16 resources -> scans\s7-ssh-refixed\resources.json
0 findings -> scans\s7-ssh-refixed\findings.json
```

## Recording into the store

The store redacts resource names and the account ID before it writes them, so the labels below are redacted.

```text
$ python scripts/demo_remediation.py --db remediation.db --claim-absent scans/s0-baseline/findings.json ... scans/s7-ssh-refixed/findings.json
step 0: scan s0-baseline (emulator) {"new": 16, "still_open": 0, "reopened": 0, "closed": 0}
  new      ASSAY-S3-003 arn:aws:s3:::REDACTED_NAME_f40e8ebc
  new      ASSAY-S3-004 arn:aws:s3:::REDACTED_NAME_f40e8ebc
  new      ASSAY-S3-005 arn:aws:s3:::REDACTED_NAME_f40e8ebc
  new      ASSAY-S3-001 arn:aws:s3:::REDACTED_NAME_7098ec97
  new      ASSAY-S3-002 arn:aws:s3:::REDACTED_NAME_7098ec97
  new      ASSAY-IAM-001 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:policy/REDACTED_NAME_86d19fa0
  new      ASSAY-IAM-002 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:policy/REDACTED_NAME_8592286f
  new      ASSAY-IAM-004 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:user/REDACTED_NAME_756d9501
  new      ASSAY-IAM-005 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:user/REDACTED_NAME_756d9501
  new      ASSAY-IAM-008 REDACTED_ACCOUNT_2f96a4ed:global:aws.iam.account
  new      ASSAY-EC2-001 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e
  new      ASSAY-EC2-003 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e
  new      ASSAY-EC2-005 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:volume/REDACTED_NAME_d640fb4f
  new      ASSAY-EC2-006 REDACTED_ACCOUNT_2f96a4ed:us-east-1:aws.ec2.region_settings
  new      ASSAY-KMS-001 arn:aws:kms:us-east-1:REDACTED_ACCOUNT_2f96a4ed:key/REDACTED_NAME_3c737140
  new      ASSAY-LOG-001 REDACTED_ACCOUNT_2f96a4ed:global:aws.cloudtrail.account
  claim  ASSAY-S3-001 arn:aws:s3:::REDACTED_NAME_7098ec97
  claim  ASSAY-S3-002 arn:aws:s3:::REDACTED_NAME_7098ec97
step 1: scan s1-s3-public (emulator) {"new": 0, "still_open": 14, "reopened": 0, "closed": 2}
  closed   ASSAY-S3-001 arn:aws:s3:::REDACTED_NAME_7098ec97 [verified]
  closed   ASSAY-S3-002 arn:aws:s3:::REDACTED_NAME_7098ec97 [verified]
  claim  ASSAY-S3-003 arn:aws:s3:::REDACTED_NAME_f40e8ebc
  claim  ASSAY-S3-004 arn:aws:s3:::REDACTED_NAME_f40e8ebc
  claim  ASSAY-S3-005 arn:aws:s3:::REDACTED_NAME_f40e8ebc
step 2: scan s2-s3-hygiene (emulator) {"new": 0, "still_open": 11, "reopened": 0, "closed": 3}
  closed   ASSAY-S3-003 arn:aws:s3:::REDACTED_NAME_f40e8ebc [verified]
  closed   ASSAY-S3-004 arn:aws:s3:::REDACTED_NAME_f40e8ebc [verified]
  closed   ASSAY-S3-005 arn:aws:s3:::REDACTED_NAME_f40e8ebc [verified]
  claim  ASSAY-EC2-003 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e
  claim  ASSAY-EC2-001 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e
  claim  ASSAY-EC2-005 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:volume/REDACTED_NAME_d640fb4f
  claim  ASSAY-EC2-006 REDACTED_ACCOUNT_2f96a4ed:us-east-1:aws.ec2.region_settings
step 3: scan s3-network-ebs (emulator) {"new": 0, "still_open": 7, "reopened": 0, "closed": 4}
  closed   ASSAY-EC2-001 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e [verified]
  closed   ASSAY-EC2-003 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e [verified]
  closed   ASSAY-EC2-005 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:volume/REDACTED_NAME_d640fb4f [verified]
  closed   ASSAY-EC2-006 REDACTED_ACCOUNT_2f96a4ed:us-east-1:aws.ec2.region_settings [verified]
  claim  ASSAY-IAM-001 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:policy/REDACTED_NAME_86d19fa0
  claim  ASSAY-IAM-004 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:user/REDACTED_NAME_756d9501
  claim  ASSAY-IAM-005 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:user/REDACTED_NAME_756d9501
  claim  ASSAY-IAM-002 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:policy/REDACTED_NAME_8592286f
  claim  ASSAY-IAM-008 REDACTED_ACCOUNT_2f96a4ed:global:aws.iam.account
step 4: scan s4-iam (emulator) {"new": 0, "still_open": 2, "reopened": 0, "closed": 5}
  closed   ASSAY-IAM-001 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:policy/REDACTED_NAME_86d19fa0 [verified]
  closed   ASSAY-IAM-002 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:policy/REDACTED_NAME_8592286f [verified]
  closed   ASSAY-IAM-004 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:user/REDACTED_NAME_756d9501 [verified]
  closed   ASSAY-IAM-005 arn:aws:iam::REDACTED_ACCOUNT_2f96a4ed:user/REDACTED_NAME_756d9501 [verified]
  closed   ASSAY-IAM-008 REDACTED_ACCOUNT_2f96a4ed:global:aws.iam.account [verified]
  claim  ASSAY-KMS-001 arn:aws:kms:us-east-1:REDACTED_ACCOUNT_2f96a4ed:key/REDACTED_NAME_3c737140
  claim  ASSAY-LOG-001 REDACTED_ACCOUNT_2f96a4ed:global:aws.cloudtrail.account
step 5: scan s5-kms-trail (emulator) {"new": 0, "still_open": 0, "reopened": 0, "closed": 2}
  closed   ASSAY-KMS-001 arn:aws:kms:us-east-1:REDACTED_ACCOUNT_2f96a4ed:key/REDACTED_NAME_3c737140 [verified]
  closed   ASSAY-LOG-001 REDACTED_ACCOUNT_2f96a4ed:global:aws.cloudtrail.account [verified]
step 6: scan s6-regression-ssh (emulator) {"new": 0, "still_open": 0, "reopened": 1, "closed": 0}
  reopened ASSAY-EC2-001 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e
  claim  ASSAY-EC2-001 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e
step 7: scan s7-ssh-refixed (emulator) {"new": 0, "still_open": 0, "reopened": 0, "closed": 1}
  closed   ASSAY-EC2-001 arn:aws:ec2:us-east-1:REDACTED_ACCOUNT_2f96a4ed:security-group/REDACTED_NAME_ba1f573e [verified]
trend: scan | observed | new | closed | reopened | active
  s0-baseline | 16 | 16 | 0 | 0 | 16
  s1-s3-public | 14 | 0 | 2 | 0 | 14
  s2-s3-hygiene | 11 | 0 | 3 | 0 | 11
  s3-network-ebs | 7 | 0 | 4 | 0 | 7
  s4-iam | 2 | 0 | 5 | 0 | 2
  s5-kms-trail | 0 | 0 | 2 | 0 | 0
  s6-regression-ssh | 1 | 0 | 0 | 1 | 1
  s7-ssh-refixed | 0 | 0 | 1 | 0 | 0
```

Every closure was earned by an emulator rescan, so each one carries `verification_status=verified`. Findings that were still open or reopened carry `not_verified`.

## The regression

`cspm diff` shows the SSH finding (id `92758b58e8af7b08`) coming back and leaving again:

```text
$ cspm diff --db remediation.db s5-kms-trail s6-regression-ssh
{
  "scan_a": "s5-kms-trail",
  "scan_b": "s6-regression-ssh",
  "added": [
    "92758b58e8af7b08"
  ],
  "removed": [],
  "persisting": [],
  "band_changed": []
}
$ cspm diff --db remediation.db s6-regression-ssh s7-ssh-refixed
{
  "scan_a": "s6-regression-ssh",
  "scan_b": "s7-ssh-refixed",
  "added": [],
  "removed": [
    "92758b58e8af7b08"
  ],
  "persisting": [],
  "band_changed": []
}
```

Its history from the store, read with `Store.history`:

```text
ASSAY-EC2-001 verified_closed verified
s0-baseline        -                -> new              not_verified
s1-s3-public       new              -> open             not_verified
(manual)           open             -> fixed_claimed    not_verified
s3-network-ebs     fixed_claimed    -> verified_closed  verified
s6-regression-ssh  verified_closed  -> reopened         not_verified
(manual)           reopened         -> fixed_claimed    not_verified
s7-ssh-refixed     fixed_claimed    -> verified_closed  verified
Counter({('verified_closed', 'verified'): 16})
```

The last line counts every finding in the store by state and verification status after step 7.

## Trend

<details><summary>cspm trend --db remediation.db (full output)</summary>

```text
$ cspm trend --db remediation.db
[
  {
    "scan_id": "s0-baseline",
    "finished_at": "2026-11-24T05:44:57+00:00",
    "mode": "emulator",
    "observed": 16,
    "by_band": {
      "critical": 5,
      "high": 3,
      "medium": 4,
      "low": 4,
      "info": 0
    },
    "new": 16,
    "reopened": 0,
    "closed": 0,
    "active_after": 16
  },
  {
    "scan_id": "s1-s3-public",
    "finished_at": "2026-11-24T05:45:55+00:00",
    "mode": "emulator",
    "observed": 14,
    "by_band": {
      "critical": 4,
      "high": 3,
      "medium": 3,
      "low": 4,
      "info": 0
    },
    "new": 0,
    "reopened": 0,
    "closed": 2,
    "active_after": 14
  },
  {
    "scan_id": "s2-s3-hygiene",
    "finished_at": "2026-11-24T05:47:02+00:00",
    "mode": "emulator",
    "observed": 11,
    "by_band": {
      "critical": 4,
      "high": 3,
      "medium": 2,
      "low": 2,
      "info": 0
    },
    "new": 0,
    "reopened": 0,
    "closed": 3,
    "active_after": 11
  },
  {
    "scan_id": "s3-network-ebs",
    "finished_at": "2026-11-24T05:48:40+00:00",
    "mode": "emulator",
    "observed": 7,
    "by_band": {
      "critical": 2,
      "high": 3,
      "medium": 1,
      "low": 1,
      "info": 0
    },
    "new": 0,
    "reopened": 0,
    "closed": 4,
    "active_after": 7
  },
  {
    "scan_id": "s4-iam",
    "finished_at": "2026-11-24T05:50:25+00:00",
    "mode": "emulator",
    "observed": 2,
    "by_band": {
      "critical": 0,
      "high": 2,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "new": 0,
    "reopened": 0,
    "closed": 5,
    "active_after": 2
  },
  {
    "scan_id": "s5-kms-trail",
    "finished_at": "2026-11-24T05:51:36+00:00",
    "mode": "emulator",
    "observed": 0,
    "by_band": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "new": 0,
    "reopened": 0,
    "closed": 2,
    "active_after": 0
  },
  {
    "scan_id": "s6-regression-ssh",
    "finished_at": "2026-11-24T05:52:32+00:00",
    "mode": "emulator",
    "observed": 1,
    "by_band": {
      "critical": 1,
      "high": 0,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "new": 0,
    "reopened": 1,
    "closed": 0,
    "active_after": 1
  },
  {
    "scan_id": "s7-ssh-refixed",
    "finished_at": "2026-11-24T05:53:57+00:00",
    "mode": "emulator",
    "observed": 0,
    "by_band": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "new": 0,
    "reopened": 0,
    "closed": 1,
    "active_after": 0
  }
]
```

</details>

Raw Terraform logs, scan outputs, the store and the per-step `main.tf` files stay in `artifacts/demo/` (ignored).
