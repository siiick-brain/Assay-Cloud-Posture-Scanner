# Scoring

Code: cspm/scoring. Entry point: `score(finding, resource, exposure) -> (score, band)`.

Every finding gets a score from 0 to 10 and a band. The score starts from the rule's base severity and moves with three pieces of context: how reachable the resource is, how much the asset matters and how sensitive its data is.

## Formula

```text
score = clamp(base + exposure + criticality + sensitivity, 0, 10), rounded to one decimal
```

Informational findings (base `info`) always score 0 so context cannot lift them into a real band.

| Input | Value | Points |
|---|---|---|
| Base severity | critical | 9.0 |
| | high | 7.5 |
| | medium | 5.0 |
| | low | 2.5 |
| | info | 0.0 |
| Exposure (from the rule's Violation) | none | +0.0 |
| | internal | +0.5 |
| | internet | +1.0 |
| `criticality` tag (default medium) | low | -1.0 |
| | medium | +0.0 |
| | high | +1.0 |
| `data_sensitivity` tag (default internal) | public | -0.5 |
| | internal | +0.0 |
| | confidential | +0.5 |
| | restricted | +1.0 |

Tag values are matched without regard to case or spaces. A missing or unknown tag value uses the default, so a typo neither hides nor inflates risk. An exposure value outside `none`, `internal` and `internet` raises `ValueError`.

## Bands

| Band | Score |
|---|---|
| critical | 9.0 or more |
| high | 7.0 to 8.9 |
| medium | 4.0 to 6.9 |
| low | above 0 and below 4.0 |
| info | 0 |

## Exposure levels set by rules

- `internet`: the misconfiguration is reachable from anywhere, for example an open security group, a public bucket, a public database, a console user without MFA, a wildcard trust or key policy, an old access key or a certificate problem on a public endpoint.
- `internal`: reachable by principals inside the account, for example an attached admin policy or a user with direct admin rights.
- `none`: hygiene gaps with no direct path in, for example missing encryption, versioning or logging.

## Worked table

| Rule | Base | Exposure | Criticality | Sensitivity | Sum | Score | Band |
|---|---|---|---|---|---|---|---|
| ASSAY-EC2-001 SSH open | high 7.5 | internet +1.0 | medium 0 | internal 0 | 8.5 | 8.5 | high |
| ASSAY-EC2-001 SSH open | high 7.5 | internet +1.0 | high +1.0 | restricted +1.0 | 10.5 | 10.0 | critical |
| ASSAY-S3-001 public bucket | high 7.5 | internet +1.0 | high +1.0 | confidential +0.5 | 10.0 | 10.0 | critical |
| ASSAY-AZ-NSG-001 any to any | critical 9.0 | internet +1.0 | medium 0 | internal 0 | 10.0 | 10.0 | critical |
| ASSAY-IAM-001 admin policy | critical 9.0 | internal +0.5 | low -1.0 | public -0.5 | 8.0 | 8.0 | high |
| ASSAY-IAM-005 old access key | medium 5.0 | internet +1.0 | medium 0 | internal 0 | 6.0 | 6.0 | medium |
| ASSAY-KMS-001 no rotation | medium 5.0 | none 0 | high +1.0 | confidential +0.5 | 6.5 | 6.5 | medium |
| ASSAY-S3-003 no encryption | medium 5.0 | none 0 | medium 0 | restricted +1.0 | 6.0 | 6.0 | medium |
| ASSAY-S3-003 no encryption | medium 5.0 | none 0 | medium 0 | internal 0 | 5.0 | 5.0 | medium |
| ASSAY-S3-004 no versioning | low 2.5 | none 0 | low -1.0 | public -0.5 | 1.0 | 1.0 | low |

## Properties checked by tests

tests/unit/test_scoring.py uses Hypothesis to check that the score stays within 0 and 10 for any severity, exposure and tag value, that the band always matches the score, and that raising exposure, criticality or sensitivity never lowers the score. The worked rows above are also fixed test cases.

## Why these numbers

A high base with internet exposure stays high (8.5) unless the asset is also tagged as important or sensitive. That keeps the critical band for issues that are both reachable and on assets that matter. The lowest possible non-info score is 1.0, so a real finding never drops to the info band.
