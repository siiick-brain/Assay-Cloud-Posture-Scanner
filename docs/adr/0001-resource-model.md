# ADR 0001: Normalized resource model

Status: accepted, 2026-11-23

Context: rules must run on AWS, Azure and Terraform plan data without knowing which API produced it.

Decision: one frozen dataclass `Resource(id, type, provider, region, config, tags)` in cspm/contracts/resource.py. `type` is a dotted name from `RESOURCE_TYPES`. Collectors flatten provider responses into `config` with documented keys per type. Account-wide settings (password policy, EBS default encryption, trail coverage) become one synthetic resource per account and region so every rule has the same shape.

Consequences: rules stay small and provider-free. Collectors carry the mapping work. Adding a resource type is a contract change.
