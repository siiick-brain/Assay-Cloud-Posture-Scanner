# CRA Annex I self-assessment

This is a self-assessment of assay-cspm against the structure of Annex I of the EU Cyber Resilience Act (Regulation (EU) 2024/2847). It is informed by the Annex and is not a conformity assessment, a declaration of conformity or a legal opinion. assay-cspm is a portfolio project, not a product placed on the market.

Requirement identifiers follow the Annex numbering. Descriptions are short paraphrases in our own words.

## Part I: properties of the product

| Ref | Our reading in brief | How assay-cspm addresses it | Evidence | Status |
|---|---|---|---|---|
| I(1) | Security proportionate to risk | Risk assessment of the scanner's own risks drives the controls | docs/risk-assessment.md | Addressed |
| I(2)(a) | No known exploitable vulnerabilities at release | Trivy config and image scans, gitleaks, locked dependencies | security.yml | Partial: image scan waits for the Dockerfile |
| I(2)(b) | Secure default configuration | No network by default, emulator mode default, live mode needs two explicit guards | docs/procedures/run-a-scan.md | Addressed |
| I(2)(c) | Security updates can be applied | Weekly rescans flag outdated dependencies. Release process | security.yml | Partial |
| I(2)(d) | Protection from unauthorised access | Credentials from environment only, read-only role, testbed endpoint refusal | docs/threat-model.md | Addressed |
| I(2)(e) | Confidentiality of data | Redaction of IDs, ARNs and secret-like values. Local files only | REQ-S-006 | Addressed |
| I(2)(f) | Integrity of data and configuration | SHA-256 manifest per report set. Frozen contracts | REQ-F-007 | Partial: manifest not signed |
| I(2)(g) | Data minimisation | Collectors read only configuration keys listed in the contract. Secret values never read | docs/contracts.md, allowlist deny list | Addressed |
| I(2)(h) | Availability of essential functions | Paginated calls and timeouts. Low priority for a local tool | docs/threat-model.md | Partial |
| I(2)(i) | Minimise impact on other services | Read-only calls only, no write path to the scanned account | ADR 0004 | Addressed |
| I(2)(j) | Limit attack surface | No listening ports, no plugins loaded at run time, small allowlist | cspm/live/allowlist.yaml | Addressed |
| I(2)(k) | Reduce incident impact | Non-root container, read-only root filesystem, short credential lifetime | REQ-S-008 | Done: Dockerfile |
| I(2)(l) | Security logging and monitoring | Scan metadata and lifecycle transitions recorded in the store | REQ-F-013 | Partial |
| I(2)(m) | Users can remove data securely | All data lives in local files the user can delete. No remote copy | docs/procedures/run-a-scan.md | Addressed |

## Part II: vulnerability handling

| Ref | Our reading in brief | How assay-cspm addresses it | Evidence | Status |
|---|---|---|---|---|
| II(1) | Know the components (SBOM) | Syft SBOM on every CI run | security.yml sbom job | Addressed |
| II(2) | Fix vulnerabilities without delay | Weekly scans. Fix and rescan procedure | docs/procedures/handle-a-finding.md | Partial |
| II(3) | Regular security testing | CI security jobs and the weekly regression oracle | ci.yml, regression.yml | Addressed |
| II(4) | Disclose fixed vulnerabilities | Changelog Security section | CHANGELOG.md | Planned |
| II(5) | Coordinated disclosure policy | Private advisory route | SECURITY.md | Addressed |
| II(6) | Contact point for reports | GitHub private security advisories | SECURITY.md | Addressed |
| II(7) | Secure distribution of updates | Releases from CI with SBOM | | Planned |
| II(8) | Updates free of charge with advisory | MIT licence, all updates public | LICENSE | Addressed |

## Results
Final results per row are in docs/evaluation.md.
