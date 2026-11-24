# Reports

`cspm.reports.write_reports(report, out_dir)` takes a report dict in the shape of `cspm/contracts/findings.schema.json` and writes one report set. `build_report(scan, findings)` builds that dict from `Finding` objects.

| File | Content |
|---|---|
| findings.json | The redacted report, validated against the frozen schema before anything is written |
| findings.sarif | SARIF 2.1.0, one rule per rule ID, one result per finding |
| report.md | Summary, counts per band, findings table and remediation per finding |
| report.html | One self-contained page with filters by severity, control and resource |
| manifest.json | SHA-256 and size of the four files above |

## Order of work

1. Redact a copy of the report (see below).
2. Restore each finding `id`. Ids are digests of the unredacted `source|rule_id|resource_id`, so the store can still match the finding on the next scan.
3. Validate against the schema. A failure raises `jsonschema.ValidationError` and writes nothing.
4. Write the four files, then the manifest.

`verify_manifest(path)` returns a list of problems: missing file, digest mismatch, a path that leaves the report folder or an empty manifest. An empty list means the set is intact.

## Redaction

`cspm.reports.redact.Redactor(salt)` runs on every string value and every dict key.

| Input | Output |
|---|---|
| AWS access key IDs (AKIA, ASIA and the other IAM prefixes) | `REDACTED_KEY_ID_<digest>` |
| Secret keys and session tokens after a key name | `REDACTED_SECRET` |
| Passwords in `password=` style text and URL credentials | `REDACTED_PASSWORD` |
| JWTs, GitHub and Slack tokens, bearer tokens | `REDACTED_TOKEN` |
| PEM private keys | `REDACTED_PRIVATE_KEY` |
| String values under keys ending in password, secret, token, api_key, private_key or credentials | `REDACTED_SECRET` |
| ARNs | account and resource name replaced; partition, service, region and resource type kept |
| Bare 12 digit account IDs | `REDACTED_ACCOUNT_<digest>` |
| Home folders in Windows and POSIX paths | user name replaced with `REDACTED_USER` |

The digest is the first 8 hex chars of SHA-256 over salt, kind and value. The same input gives the same placeholder, so a resource keeps its name across scans. Secrets get no digest because a digest of a short password can be reversed by guessing. Without a salt an account ID digest can be brute forced, so pass a private salt for reports that leave the machine. Hex digests and numbers longer than 12 digits are left alone.

`python -m cspm.reports.redact SRC DST` redacts one JSON or text file. The recorded tool outputs in fixtures/recorded/ went through it.

## HTML

All CSS and JS sit inline. A Content-Security-Policy meta tag sets `default-src 'none'`, so the browser refuses any outside fetch even if a value slipped through. Reference URLs show as plain text, never as links. The test parses the page and fails on any `src` or `href` to an http(s) host, any `<link>` tag and any CSS `url()` or `@import` pointing outside.

## SARIF

`security-severity` holds the 0 to 10 score as a string, which GitHub code scanning reads. `partialFingerprints.assayFindingId/v1` holds the finding id. When evidence carries `file` and `start_line` the result also gets a physical location. The official SARIF JSON schema is not stored offline (fetching it needs a download the lane was not cleared for), so tests check the required members by structure instead of full schema validation.
