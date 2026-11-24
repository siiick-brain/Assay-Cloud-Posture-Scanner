# Run a scan

Three modes exist. Emulator and fixture modes are the normal ones. Live mode is optional and manual. Check `uv run cspm scan --help` for the exact flags once the CLI lands.

## Emulator mode (default for development)
1. Start Moto on loopback: `docker compose -f docker/compose.yaml up -d moto`. Set `MOTO_HOST_PORT` if port 5000 is taken.
2. Export fake credentials. Moto accepts anything and nothing leaves the machine.

```sh
export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:5000
```

3. Apply a testbed stack: `terraform -chdir=testbed/insecure init` then `terraform -chdir=testbed/insecure apply`.
4. Scan and write reports: `uv run cspm scan --provider aws --mode emulator --out out/insecure`.
5. Open the HTML report in out/insecure or read the JSON.

Testbed mode refuses any endpoint other than localhost or the Moto container. A stray endpoint variable cannot send the scan to AWS.

## Fixture mode
Azure and Terraform plan input come from files: `uv run cspm scan --provider azure --mode fixture --source testbed/azure-fixtures`.

## Live mode (manual, never in CI)
Only with a read-only role in a sandbox or member account. Never a root, billing or management account.
1. Set a billing alarm in the account first.
2. Get short-lived credentials for a role with only SecurityAudit and ViewOnlyAccess. See rotate-scanner-credentials.md.
3. Run with both guards: `CSPM_ALLOW_LIVE=1 uv run cspm scan --provider aws --live --out out/live`.
4. Redact account IDs, ARNs and resource names before sharing any output.

The allowlist hook blocks every call outside cspm/live/allowlist.yaml even if the role is wider than it should be.

## OpenSCAP container scan
`sh scripts/openscap/run.sh all` builds the scanner and target images, scans, hardens and scans again. Results go to artifacts/openscap/. See docs/hardening.md.
