# Changelog

All notable changes to this project are listed here. The format follows Keep a Changelog and the project uses semantic versioning once it has a first release.

## [Unreleased]

### Added
- Frozen contracts at tag contracts-v1: resource model, finding model, rule interface with 33 rule IDs, findings JSON schema 1.0.0 and the read-only AWS allowlist.
- Commit hooks for author, title and banned words plus scripts/check-style.ps1.
- Requirements, threat model, architecture and ADRs 0000 to 0004.
- CI workflows: ruff, mypy strict, tests with an 85 percent coverage gate, Moto emulator integration, allowlist static check, style and authorship check.
- Security workflow: Trivy config and image scans, gitleaks and a Syft SBOM artifact.
- Weekly testbed regression workflow that compares finding counts with testbed/ground-truth.yaml.
- scripts/check_allowlist.py, a static check that every boto3 client call in cspm/ is on the allowlist.
- OpenSCAP scanner and Ubuntu 24.04 target images, hardening script and recorded before and after results.
- cspm.ingest.xccdf for OpenSCAP XCCDF results.
- Procedures, risk assessment, secure development checklist, CRA Annex I self-assessment, docs index and Mermaid diagrams.

### Changed

### Fixed

### Security
