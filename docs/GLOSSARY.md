# Glossary

| Term | Meaning here |
|---|---|
| CSPM | Cloud security posture management. Finds risky configuration in cloud accounts. |
| CNAPP | Cloud-native application protection platform. CSPM plus workload, image and identity protection. |
| Resource | One normalized cloud object (cspm/contracts/resource.py). |
| Rule | Code that checks one resource type for one issue and has a frozen ID. |
| Finding | One rule violation on one resource, with evidence and a score. |
| Severity base | The starting severity a rule assigns before scoring adjusts it. |
| Band | The severity level that the 0 to 10 score falls into. |
| Exposure | How reachable a resource is: none, internal or internet. |
| Ground truth | testbed/ground-truth.yaml, the list of seeded misconfigurations. |
| Recall | Seeded misconfigurations found divided by seeded misconfigurations. |
| Emulator | Moto running in process or as moto_server. Stands in for AWS in tests. |
| Fixture | Recorded or synthetic JSON used instead of a live API. |
| Verification status | How strongly a closure is backed: verified, observed_unverified or not_verified. |
| Allowlist | cspm/live/allowlist.yaml. The only AWS operations the scanner may call. |
| XCCDF | The result format OpenSCAP writes after a benchmark scan. |
| SARIF | Static analysis results format read by GitHub code scanning. |
