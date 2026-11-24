# Threat model

Scope: the scanner process, its credentials, its local SQLite store, the reports it writes and the CI pipeline. The scanned cloud account is an asset we protect from the scanner itself.

## Assets
- Scanner credentials (short-lived role session in live mode).
- Collected configuration, which reveals the account layout.
- Findings store and reports, which list every weakness.
- The CI pipeline and release artifacts.

## Trust boundaries
1. Operator shell to scanner process (environment variables).
2. Scanner to cloud API (boto3 over TLS, allowlist hook).
3. Scanner to local disk (store, reports, recorded fixtures).
4. Repository to CI runner.

## STRIDE

| Threat | Example | Mitigation | Requirement |
|---|---|---|---|
| Spoofing | Testbed run pointed at a real endpoint by a stray AWS_ENDPOINT_URL | Testbed mode refuses any host other than localhost or the Moto container | REQ-S-003 |
| Tampering | A rule or collector change that starts calling a write API | Runtime allowlist hook plus static check in CI | REQ-S-001, REQ-S-002 |
| Tampering | Report edited after the scan | SHA-256 manifest per report set | REQ-F-007 |
| Repudiation | Nobody can tell which scan closed a finding | Store keeps scan ID, mode and verification_status on every transition | REQ-F-013, REQ-F-014 |
| Information disclosure | Secret value copied into evidence | Collectors never call GetSecretValue. Evidence redaction before storage | REQ-S-006, REQ-S-011 |
| Information disclosure | Account IDs in committed fixtures or screenshots | Redaction step and OCR check before commit | REQ-S-006 |
| Information disclosure | Credentials written to logs | Credentials only read from the environment and never logged | REQ-S-005 |
| Denial of service | Huge account makes the scan hang | Paginated calls and per-service timeouts. Not a priority for a portfolio scanner | none |
| Elevation of privilege | Scanner role has more than read access | Role limited to SecurityAudit and ViewOnlyAccess. Hook still blocks writes if the role is wider | REQ-S-001 |
| Elevation of privilege | Compromised dependency runs code in CI | Hash-pinned dependencies, SHA-pinned actions, least-privilege workflow tokens | REQ-S-009 |

## Attack tree: steal the scanner's credentials

```text
Goal: obtain credentials that can read or change the target account
  OR  Read them from disk
        AND  Credentials were written to a file (blocked: env only, REQ-S-005)
        AND  Attacker has local file access
  OR  Read them from logs or reports
        AND  Logger or evidence captured env or headers (blocked: redaction, REQ-S-006)
  OR  Steal them in CI
        AND  CI holds cloud credentials (blocked: CI never has any, cloud rule)
        OR   Malicious dependency or action exfiltrates runner env (reduced: hash and SHA pins, REQ-S-009)
  OR  Phish the operator for a long-lived key
        AND  Operator uses static keys (reduced: live mode documents short-lived role sessions only)
  OR  Abuse stolen credentials for writes
        AND  Role allows writes (reduced: SecurityAudit and ViewOnlyAccess only)
        AND  Hook bypassed (blocked in scanner code, does not stop an attacker using the keys directly)
```

Residual risk: the hook protects against our own code. It does nothing once an attacker holds the keys outside the scanner, so short session lifetimes and a read-only role carry that case.
