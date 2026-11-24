# Usage

`cspm` makes no network calls unless you point it at the emulator or pass `--live`.

## Commands

| Command | What it does | Backed by |
|---|---|---|
| `cspm scan` | Collects resources, writes `resources.json`, then runs rules into `findings.json` when the engine is present | collectors, cspm.engine |
| `cspm report --input findings.json --out reports/` | Renders the report set and manifest | cspm.reports |
| `cspm diff OLD NEW --db cspm.db` | Compares two recorded scans | cspm.store |
| `cspm trend --db cspm.db` | Finding counts over time | cspm.store |
| `cspm iam-review --policy p.json [--requirements r.yaml]` | Least-privilege review | cspm.iam |
| `cspm tls-check HOST [PORT]` | TLS and certificate checks. Hosts off this machine need `--live` | cspm.tls |
| `cspm map-coverage [--json] [--min-frameworks 3]` | Frameworks mapped per rule | cspm.mapping |

A command whose module is missing prints `<module> is not available in this install` and exits with code 3. Refused endpoints and missing live switches exit with code 2.

## scan

```bash
cspm scan --provider aws --mode emulator --endpoint http://localhost:5000 --out out/aws
cspm scan --provider azure --mode fixture --source testbed/azure-fixtures/insecure --out out/azure
cspm scan --provider terraform --mode fixture --source testbed/plans/insecure.plan.json --out out/plan
```

- `--mode` defaults to `emulator` for AWS and `fixture` for the others.
- Emulator mode accepts only `localhost`, `127.0.0.1`, `::1` and `moto` as hosts and always uses the dummy keys `testing`/`testing`, so real keys never reach an emulator.
- `--now` sets the scan clock: an ISO 8601 time or `+Nd`. Testbed scans use `+120d` (see testbed/README.md).
- `--region` repeats. The default is `AWS_DEFAULT_REGION` or `us-east-1`.

## Live mode

Live mode needs `--live` and `CSPM_ALLOW_LIVE=1` together. Credentials come only from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. Every boto3 client carries a hook that blocks any call not on cspm/live/allowlist.yaml before it is signed. Azure live mode reads `AZURE_SUBSCRIPTION_ID` and `EnvironmentCredential`; it is Not verified.

## Docker

```bash
docker build -t assay-cspm .
docker network create assay-net
docker network connect --alias moto assay-net <moto-container>
docker run --rm --read-only --tmpfs /tmp --network assay-net -v "$PWD/out:/out" \
  assay-cspm scan --provider aws --mode emulator --endpoint http://moto:5000 --out /out
```

The image installs hash-pinned dependencies from requirements.lock, runs as UID 10001 and ships `mappings/` with `CSPM_MAPPINGS_DIR=/app/mappings`. Regenerate the lock with `uv export --no-dev --format requirements-txt --no-emit-project -o requirements.lock`.
