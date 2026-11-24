# Recorded tool output (Item 8)

Real runs on 2026-11-23 on the build machine (Windows 11, no cloud account, no credentials). Every file below is the tool's own JSON, passed through `python -m cspm.reports.redact` and nothing else. Large files are gzipped (minified JSON, same content). Redaction replaced the user name in absolute paths and the `password = var.db_password` line in code snippets (a variable reference, not a secret, but the redactor is cautious). No account IDs or ARNs appeared in any output.

## Target

The Lane B testbed Terraform did not exist yet when these runs were made (`..\lane-ab\testbed` held only placeholders). `trivy/sample-tf/main.tf` is a small insecure stand-in written for this lane: 14 seeded issues on 7 resources plus two resources meant to be clean. The seeded list is in `sample-ground-truth.yaml`. Rescan the testbed after Lane B merges.

## Tools

| Tool | Version | Licence | Install |
|---|---|---|---|
| Trivy | 0.76.2, vuln DB v2 updated 2026-11-23 19:02 UTC, check bundle sha256:b591e919 | Apache-2.0 | preinstalled binary |
| Checkov | 3.4.7 | Apache-2.0 | `python -m uv tool install --python 3.12 checkov` (isolated tool env) |
| Prowler | 5.52.0 | Apache-2.0 | `python -m uv tool install --python 3.12 prowler` (isolated tool env) |

## Runs

| File | Command (from the lane-df worktree root) | Result |
|---|---|---|
| trivy/config-sample-tf.json | `trivy config --format json --output <f> fixtures/recorded/trivy/sample-tf` | 24 failures, 23 after merging two AWS-0107 rows for one group |
| trivy/fs-repo.json | `trivy fs --scanners vuln,secret,misconfig --skip-dirs .venv --skip-dirs artifacts --skip-dirs .git --format json --output <f> .` | uv.lock: 0 vulnerabilities; sample-tf: same 24 misconfigurations; 5 secret hits, all in `.pytest_cache` (see below) |
| trivy/image-python312-slim.json.gz | `trivy image --scanners vuln,secret --format json --output <f> python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b` | python:3.12-slim (Debian 13.7): 252 OS package CVEs, 6 Python package CVEs, 36 with a fixed version, 0 secrets |
| checkov/sample-tf.json | `checkov -d fixtures/recorded/trivy/sample-tf --framework terraform -o json --quiet --compact --skip-download` | 44 failed, 34 passed, 14 resources |
| prowler/iac-sample-tf.ocsf.json.gz | `prowler iac --scan-path fixtures/recorded/trivy/sample-tf --output-formats json-ocsf --output-directory <d> --output-filename prowler-iac-sample-tf --no-banner --no-color -z` with `PYTHONUTF8=1` | 24 FAIL, 74 PASS |

Notes on the runs:

- The scanner image is built by Lane A and did not exist yet. The image row uses the public `python:3.12-slim` pinned by digest. Rescan the scanner image after merge.
- The `trivy fs` secret hits are false positives from this lane's own redaction tests: pytest writes parametrized test ids, which hold synthetic tokens, into `.pytest_cache/v/cache/nodeids`. The directory is gitignored. Trivy keeps the matched text in its JSON; the redactor replaced it.
- The first Prowler run wrote the same OCSF file but exited 1 when printing its summary table (`UnicodeEncodeError` from the Windows cp1252 console). The recorded file is from the rerun with `PYTHONUTF8=1`, which exited 0.
- Prowler 5.52.0 offers these providers without a cloud account: `iac` (local folder or repo, runs Trivy inside), `image` (container images, also Trivy) and `kubernetes` (needs a reachable cluster). Only `iac` is recorded. The `kubernetes` provider was tried and picked up the default kubeconfig context, which points at a local kind cluster on 127.0.0.1 that this project did not create. That output is not recorded. A recorded Kubernetes row needs a kind cluster created for this project.

## Testbed and scanner image runs (2026-11-24)

Real runs on 2026-11-24 on the same machine, from the lane-scans worktree root (branch lane/scans, integration commit b11e7e1). Same tool versions as above: Trivy 0.76.2 with the same vuln DB and check bundle, Checkov 3.4.7 and Prowler 5.52.0 from the same uv tool envs. Docker 29.9.2. Targets are `testbed/insecure` and `testbed/secure` (Lane B). Each output went through `python -m cspm.reports.redact`; the Prowler files were then minified and gzipped. Redaction replaced the user name in absolute paths and nothing else in these files.

| File | Command | Result |
|---|---|---|
| trivy/testbed-insecure.json, trivy/testbed-secure.json | `trivy config --format json --output <f> testbed/<stack>` | insecure 17 failures, secure 5 |
| checkov/testbed-insecure.json, checkov/testbed-secure.json | `checkov -d testbed/<stack> --framework terraform -o json --quiet --compact --skip-download` | insecure 39 failed, secure 19 failed (exit 1, which means failed checks) |
| prowler/testbed-insecure.json.gz, prowler/testbed-secure.json.gz | `prowler iac --scan-path testbed/<stack> --output-formats json-ocsf --output-directory <d> --output-filename prowler-iac-testbed-<stack> --no-banner --no-color -z` with `PYTHONUTF8=1` | insecure 17 FAIL and 66 PASS, secure 5 FAIL |
| trivy/image-assay-cspm.json | `docker build -t assay-cspm:dev .` then `trivy image --scanners vuln,secret --format json --output <f> assay-cspm:dev` | image sha256:1f482604be92 (Debian 13.7): 258 vulnerabilities (54 high, 106 medium, 82 low, 16 unknown), 36 with a fixed version, 0 secrets |
| trivy/fs-repo-integration.json | `trivy fs --scanners vuln,secret,misconfig --skip-dirs .venv --skip-dirs artifacts --skip-dirs .git --format json --output <f> .` | uv.lock 0 vulnerabilities, 0 secrets, 5 Dockerfile and 66 Terraform misconfiguration rows |

Notes:

- Prowler ran only with the `iac` provider, named on the command line, with `KUBECONFIG` pointed at a file that does not exist and no AWS variables set. No Kubernetes context and no cloud provider was touched.
- `testbed-ground-truth-tf.yaml` restates the 16 AWS entries of `testbed/ground-truth.yaml` by Terraform address so `cspm.ingest.compare` can score IaC findings. It was written from the ground truth, not from tool output.
- The image file is trimmed: each vulnerability keeps only the fields `cspm.ingest` reads (id, package, installed and fixed version, status, severity, title, primary URL) and a `TrimmedBy` block holds the severity counts. The full output was 1.2 MB.
- The image findings are the base image's. `python:3.12-slim` by the same digest gave the same 252 Debian and 6 pip CVEs on 2026-11-23; the hash-pinned project dependencies add none.
- `trivy fs` changed since the 2026-11-23 run: the repo now holds the testbed and three Dockerfiles, and this fresh worktree has no `.pytest_cache`, so the 5 secret false positives are gone. Trivy also builds one extra root module named `main.tf` from both testbed stacks together (20 failures). The 2026-11-23 file `trivy/fs-repo.json` stays because it is the only real sample of Trivy secret output.
