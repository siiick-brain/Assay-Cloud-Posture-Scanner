# References

Project tools with a real run, the pinned version and the licence.

| Tool | Version | Licence | Used for | Status |
|---|---|---|---|---|
| Trivy | 0.76.2 (vuln DB v2 of 2026-11-23, check bundle sha256:b591e919) | Apache-2.0 | Item 8: `trivy config` on the sample Terraform, `trivy fs` on the repo, `trivy image` on python:3.12-slim by digest | verified, fixtures/recorded/trivy |
| Checkov | 3.4.7 | Apache-2.0 | Item 8: Terraform scan of the sample, comparison column | verified, fixtures/recorded/checkov |
| Prowler | 5.52.0 | Apache-2.0 | Item 8: `prowler iac` on the sample Terraform | verified, fixtures/recorded/prowler. Kubernetes provider not verified: no project cluster |
| OpenSCAP | 1.3.9 | LGPL-2.1-or-later | Item 11: container hardening scan | verified |
| SCAP Security Guide | 0.1.82 (upstream zip, sha256 pinned) | BSD-3-Clause | Item 11: Ubuntu 24.04 content | verified |
| python:3.12-slim image | sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b | PSF and Debian package licences | Item 8 base image scan target | scan target only |

Run commands, dates and redaction notes for Item 8: fixtures/recorded/README.md.
