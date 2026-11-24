# Repository metadata

Proposed settings for the GitHub page. The owner applies them when the repo goes public.

## Description (under 350 characters)
Read-only cloud security posture scanner for AWS and Azure. Scores findings, writes JSON, SARIF and offline HTML reports, maps rules to seven frameworks (informed by, no compliance claim) and tracks fixes through rescans. Tested against a Moto emulator only.

## Website
Leave empty until there is a hosted sample report.

## Topics
cspm, cloud-security, aws, azure, security-scanner, posture-management, boto3, moto, sarif, openscap, terraform, python, iam, devsecops

## Social preview (1280 x 640)
- Left: project name and the one line "Read-only posture scanner for AWS and Azure".
- Right: a crop of the HTML report filtered to high severity, taken from a real emulator scan.
- Blur or crop any resource names even though they come from the testbed.
- Dark background, no logos of cloud providers or standards bodies.
- Social preview: docs/images/report-html.png cropped to 1280 by 640.

## Repository settings
- Features: Issues on, Discussions off, Wiki off, Projects off.
- Private vulnerability reporting on, to match SECURITY.md.
- Branch protection on main: require the ci and security workflows, no force pushes.
- Actions: allow only actions pinned by full SHA. Default workflow token permission read-only.
- Releases: attach the SBOM artifact from security.yml.

## Pinned README badges
The ci and security workflows pass on GitHub. Badges for CI status and licence can go at the top of README.md.
