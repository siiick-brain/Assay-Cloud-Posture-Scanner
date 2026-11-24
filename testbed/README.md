# Testbed

Emulator only. Both Terraform stacks point every endpoint at the Moto server on `http://localhost:5000` with the Moto dummy keys. Never apply them anywhere else.

| Path | What it holds |
|---|---|
| insecure/ | AWS stack with every seeded issue |
| secure/ | The same shape with each issue fixed. A scan must find nothing |
| azure-fixtures/insecure, azure-fixtures/secure | Synthetic ARM-shaped JSON, each file labelled `"synthetic": true` |
| ground-truth.yaml | `expected_finding_count` plus one `ground_truth` entry per expected finding |
| recorded/ | Collector output from real Moto runs, each file a list of `Resource.to_dict()` |
| plans/ | `terraform show -json` output for both stacks, input for the plan collector |
| apply.sh | Resets Moto and applies one stack |

## Running

```bash
docker run -d --name assay-moto -p 5000:5000 motoserver/moto:5.2.6
testbed/apply.sh insecure          # logs go to artifacts/
cspm scan --provider aws --mode emulator --now +120d --out out/insecure
testbed/apply.sh secure
cspm scan --provider aws --mode emulator --now +120d --out out/secure
```

Both stacks share one emulator, so `apply.sh` resets Moto before each apply. The AWS provider is pinned to 4.67.0: with 5.x the Go SDK sends a short CloudTrail `X-Amz-Target` that Moto 5.2.6 answers with 404.

## Scan clock and access key age

Rules read time from `ScanContext.now`. Moto stamps the access key with the apply time, so the key is new when the stack comes up. Testbed scans run with `--now +120d` (scan time plus 120 days), which puts the key past the 90 day limit of ASSAY-IAM-005. The secure stack has no access keys, no secrets and no certificates, so the shifted clock cannot add findings there. `expected_finding_count` assumes this clock. A scan with the real clock gives one finding less.

## Matching ground truth to resources

`resource_name` means:
- S3 bucket, security group, IAM policy, IAM user: the resource name.
- EBS volume and KMS key: the `Name` tag.
- `aws.ec2.region_settings`: the region (`us-east-1`).
- `aws.iam.account` and `aws.cloudtrail.account`: the literal `account`.
- Azure: the ARM `name`.

ASSAY-IAM-002 is seeded on a policy with `s3:*`. The policy with `Action: "*"` counts as ASSAY-IAM-001 only. The security group opens only tcp 22 and tcp 5432, so only ASSAY-EC2-001 and ASSAY-EC2-003 apply. The log bucket grants the S3 LogDelivery group, which is not public.

## Redaction

Recorded files and plans keep Moto's default account ID 123456789012. It is synthetic and belongs to no one. The plans also contain the Moto dummy keys `testing`/`testing`, which grant nothing.
