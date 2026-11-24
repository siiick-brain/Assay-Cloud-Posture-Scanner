# Frozen contracts (contracts-v1)

Code: cspm/contracts/. Schema: cspm/contracts/findings.schema.json. Allowlist: cspm/live/allowlist.yaml. Change any of these only in a small change of its own, with a version bump where the schema changes.

## Resource

`Resource(id, type, provider, region, config, tags)`. `id` is the ARN for AWS, the resource ID for Azure and the Terraform address for plan input. Account-level types use `id = "<account>:<region>:<type>"`. Region is `global` for IAM.

## Config keys per resource type

Collectors must fill every key listed (use the default when the API returns nothing). Rules read only these keys. Times are ISO 8601 UTC strings. Policy documents are parsed dicts, never JSON strings.

| Type | Keys (default) |
|---|---|
| aws.s3.bucket | `name`, `acl_grants` (list of {grantee_uri, permission}), `policy` (dict or null), `policy_is_public` (bool, false), `public_access_block` ({block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets}, all false when absent), `encryption` ({algorithm, kms_key_id} or null), `versioning` ("Enabled", "Suspended" or "Disabled"), `logging_enabled` (bool) |
| aws.ec2.security_group | `group_id`, `name`, `vpc_id`, `ingress` (list of {protocol, from_port, to_port, cidrs, ipv6_cidrs}; protocol "-1" means all, ports null for all) |
| aws.ec2.volume | `volume_id`, `encrypted` (bool), `kms_key_id` (str or null), `attached_instance_ids` (list) |
| aws.ec2.region_settings | `ebs_encryption_by_default` (bool) |
| aws.rds.instance | `identifier`, `engine`, `publicly_accessible` (bool), `storage_encrypted` (bool), `security_group_ids` (list) |
| aws.iam.policy | `name`, `arn`, `document` (dict), `attached` (bool), `aws_managed` (bool) |
| aws.iam.user | `name`, `has_console_password` (bool), `mfa_devices` (int), `access_keys` (list of {key_id_suffix, status, created}), `attached_policy_arns` (list), `inline_policies` (list of {name, document}) |
| aws.iam.role | `name`, `trust_policy` (dict), `attached_policy_arns` (list), `inline_policies` (list of {name, document}) |
| aws.iam.account | `root_access_keys_present` (bool), `root_mfa_enabled` (bool), `password_policy` (dict or null with minimum_length, require_symbols, require_numbers, require_uppercase, require_lowercase, max_age_days) |
| aws.cloudtrail.trail | `name`, `is_multi_region` (bool), `is_logging` (bool), `log_file_validation` (bool), `home_region` |
| aws.cloudtrail.account | `trail_names` (list), `has_logging_multi_region_trail` (bool) |
| aws.kms.key | `key_id`, `manager` ("CUSTOMER" or "AWS"), `state`, `rotation_enabled` (bool), `policy` (dict or null), `key_spec` |
| aws.secretsmanager.secret | `name`, `rotation_enabled` (bool), `last_rotated` (str or null), `created` (str) |
| aws.acm.certificate | `domain`, `not_after` (str), `key_algorithm` (e.g. "RSA_1024", "RSA_2048", "EC_prime256v1"), `signature_algorithm` (e.g. "SHA256WITHRSA"), `status` |
| azure.storage.account | `name`, `https_only` (bool), `min_tls_version` (str), `allow_blob_public_access` (bool) |
| azure.storage.container | `name`, `account`, `public_access` ("None", "Blob" or "Container") |
| azure.network.nsg | `name`, `security_rules` (list of {name, direction, access, protocol, source_address_prefix, destination_port_range, priority}) |
| azure.keyvault.vault | `name`, `purge_protection` (bool), `soft_delete` (bool) |
| azure.compute.disk | `name`, `encryption_type` (str or null), `encryption_enabled` (bool) |

## Tags used by scoring

`criticality`: low, medium, high (default medium). `data_sensitivity`: public, internal, confidential, restricted (default internal). Testbed resources carry these tags.

## Finding

See cspm/contracts/finding.py. `id` is the first 16 hex chars of SHA-256 over `source|rule_id|resource_id`. `state` and `verification_status` are separate fields. A rescan in emulator or fixture mode earns `verified`, a live rescan earns `observed_unverified`, no rescan stays `not_verified`.

## Lifecycle

```text
new -> open -> assigned -> fixed_claimed -> verified_closed
                                 |               |
                                 v               v
                              reopened <---- rescan still fails / issue returns
```

## Rule interface

`Rule.meta: RuleMeta` and `Rule.evaluate(resource, ctx) -> list[Violation]`. `Violation.exposure` is one of `EXPOSURE_LEVELS`. Rule IDs and base severities are in cspm/contracts/rule_ids.py (33 IDs).

## Module interfaces

| Module | Entry point | Owner |
|---|---|---|
| cspm.collectors | `collect(provider: Provider, *, mode: ScanMode, source: str | None) -> list[Resource]` | A |
| cspm.engine | `run_rules(resources: Sequence[Resource], ctx: ScanContext) -> list[Finding]` | C |
| cspm.scoring | `score(finding: Finding, resource: Resource, exposure: str) -> tuple[float, Severity]` | C |
| cspm.mapping | `controls_for(rule_id: str) -> list[ControlRef]` | E |
| cspm.reports | `write_reports(report: dict, out_dir: Path) -> Path` (returns manifest path) | D |
| cspm.store | `Store(path).record_scan(scan_meta, findings) -> ScanDiff` | D |
| cspm.ingest | `ingest(tool: Source, path: Path) -> list[Finding]` | F |
| cspm.iam | `review(policy: dict, requirements: dict) -> ReviewResult` | G |
| cspm.tls | `check_endpoint(host: str, port: int) -> list[Violation]` | G |
