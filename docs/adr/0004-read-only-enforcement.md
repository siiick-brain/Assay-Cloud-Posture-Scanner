# ADR 0004: Read-only enforcement

Status: accepted, 2026-11-23

Context: a posture scanner must never change the account it scans, even when the role it runs under is wider than intended.

Decision: two layers.
1. Runtime: a botocore `before-call` handler registered on every client checks `service:operation` against cspm/live/allowlist.yaml. The operation must be listed, must start with Describe, List or Get and must not be in `deny`. Anything else raises before the request is signed.
2. Static: a CI check scans cspm/ for boto3 client method calls and fails if any maps to an operation that is not on the list.

The live role is limited to SecurityAudit and ViewOnlyAccess. That is the third layer and the only one outside our code.

Consequences: adding a collector call means adding the operation to the allowlist in the same change, which makes new API use visible in review.
