# CSPM, CNAPP and where assay-cspm fits

## Terms

A cloud security posture management (CSPM) tool reads the configuration of cloud accounts through the provider APIs and compares it against a rule set. It answers one question: is this account set up in a risky way right now? Typical checks are public storage, open admin ports, missing encryption, weak IAM and logging that is off. Good CSPM tools also track findings over time, map them to frameworks and point to the fix.

A cloud native application protection platform (CNAPP) bundles CSPM with the other layers that protect a cloud workload. Vendors draw the line in different places, but the usual parts are:

| Layer | What it looks at |
|---|---|
| CSPM | Live cloud configuration through the control plane API |
| IaC scanning | Terraform, CloudFormation, Kubernetes manifests before deploy |
| CIEM | Who can do what: effective permissions, unused rights, escalation paths |
| CWPP | The running workload: hosts, containers, serverless, with an agent or snapshot scan |
| Image and dependency scanning | Known CVEs in OS packages and libraries, secrets in images |
| Data security posture | Where sensitive data sits and who can reach it |
| Runtime detection | Suspicious behaviour while the workload runs, often from audit logs or eBPF |
| Attack path analysis | Joins the above into a graph to rank what an attacker could chain |

## What assay-cspm covers

| Area | Coverage | Where |
|---|---|---|
| Posture rules on AWS and Azure configuration | Yes, 33 rules over 19 resource types | rules/, cspm/engine |
| Terraform plan input | Yes, the same rules run on a plan | cspm/collectors |
| Risk score from severity, exposure and tags | Yes | cspm/scoring |
| Framework mapping | Informed by seven frameworks, no compliance claim | mappings/, cspm/mapping |
| Finding lifecycle, SLA and rescan verification | Yes | cspm/store |
| Reports | JSON, SARIF, Markdown, offline HTML | cspm/reports |
| IAM least-privilege review | Static policy review against a declared need | cspm/iam |
| Certificate, key and TLS checks | Yes | cspm/tls, rules |
| Image, package and secret scanning | Not built in. Trivy output is ingested instead | cspm/ingest |
| Other IaC rule sets | Not built in. Trivy and Checkov output is ingested | cspm/ingest |
| Host hardening | OpenSCAP results are ingested | cspm/ingest/xccdf.py |
| CIEM with effective permissions across accounts | No | |
| Workload protection, runtime detection | No | |
| Data discovery | No | |
| Attack path graph | No. Exposure is one input to the score, not a graph | |
| Continuous monitoring and auto remediation | No. Scans run on demand and fixes are manual | |

## Position

assay-cspm is a small CSPM with a lifecycle store and evidence reports. It is not a CNAPP. It reaches into the neighbouring layers by importing results from tools that already do them well (Trivy for images, packages, secrets and IaC, Checkov for IaC, Prowler where it runs without an account, OpenSCAP for hosts) and putting them in the same finding model, with a source label and deduplication against its own rules. That keeps one report and one lifecycle without rebuilding those scanners.

The scanner is read-only by design. It never changes a cloud resource and live mode runs only against an allowlist of Describe, List and Get calls. Tests and the testbed use the Moto emulator and recorded fixtures, never a real account.
