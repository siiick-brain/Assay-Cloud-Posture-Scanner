# ADR 0003: Emulator choice

Status: accepted, 2026-11-23

Context: tests, CI and the testbed must run with no AWS account, no sign-up and no paid tier.

Options checked on 2026-11-23:
- LocalStack: since the single-image release in March 2026 the image needs an auth token tied to an account. Fails the no-account rule.
- floci (floci-io/floci): MIT licence, free, no account. Younger project with less coverage history. Kept as fallback.
- Moto: Apache-2.0, no account, runs in process for unit tests and as moto_server in Docker for Terraform and integration tests.

Decision: Moto. Unit tests use the in-process mock. The testbed and integration tests use the motoserver/moto image on localhost:5000, which Terraform targets through provider endpoint overrides. Azure uses synthetic fixtures only.

Consequences: Moto does not model every field (for example some S3 public access evaluation). Rules must not depend on fields Moto cannot set. Gaps get recorded as Not verified rows.
