# TLS, certificate and key checks

Code lives in `cspm/tls/`. `cspm tls-check` calls `main_tls_check(argv) -> int`.

## Certificate checks

`check_certificate(cert, now, *, warn_days=30)` and `check_certificate_file(path, now)` take PEM or DER. Each failed check returns one `Violation` whose evidence has `check`, `severity`, `subject` and `serial`.

| check | severity | Trigger |
|---|---|---|
| expired | high | `now` is past notAfter |
| expiring | medium | fewer than `warn_days` days left |
| not_yet_valid | medium | `now` is before notBefore |
| weak_key | high | RSA or DSA under 2048 bits, EC under 256 bits |
| weak_signature | high | SHA-1, MD5 or a hash cryptography cannot parse |
| self_signed | low | issuer equals subject and the cert verifies with its own key |

cryptography refuses SHA-1 and MD5 in its issuer check, so for those certs we verify the RSA signature by hand.

## Key management checks

Both functions take a boto3 client and call only read-only operations listed in `cspm/live/allowlist.yaml`.

- `check_kms_rotation(kms)`: ListKeys, DescribeKey and GetKeyRotationStatus. Flags enabled customer managed symmetric keys with rotation off. AWS managed keys, asymmetric keys and keys pending deletion are skipped.
- `check_secret_age(secrets, now, *, max_age_days=90)`: ListSecrets only. Uses LastRotatedDate, or CreatedDate when the secret was never rotated. It never reads a secret value.

`tests/unit/test_tls_keys.py` runs both against moto's in-process mock and records every operation through a botocore `before-call` hook, then asserts each one is on the allowlist and not on the deny list.

## Endpoint checker

`check_endpoint(host, port, *, ca_bundle=None, server_hostname=None, allow_remote=False, now=None, timeout=5.0)` returns a list of `Violation`. `scan_endpoint` takes the same arguments and returns an `EndpointReport` that also lists protocol and cipher probe states, including probes the local OpenSSL could not run.

Hosts that resolve to anything other than loopback raise `RemoteHostRefused` unless `allow_remote=True`. We do not scan hosts we do not own.

| check | severity | Trigger |
|---|---|---|
| legacy_protocol | high | the server completes a TLS 1.0 or 1.1 handshake |
| no_modern_protocol | high | neither TLS 1.2 nor 1.3 is accepted |
| tls10_cbc | medium | TLS 1.0 is accepted with a CBC suite |
| weak_cipher | high | the server accepts an RC4, 3DES, NULL, EXPORT or anonymous suite |
| chain_invalid | high | the chain or name fails against `ca_bundle` (system store when omitted) |
| modern_handshake_failed | high | a default client cannot connect at all |
| certificate checks | as above | run on the leaf the server sends |

Probes use the stdlib `ssl` module at OpenSSL security level 0 so the client can offer legacy versions and suites. A probe is marked `untestable` when our own client cannot offer it, which is different from the server rejecting it.

## Local test servers

`tests/tls_servers/` starts threaded TLS servers on 127.0.0.1. Certificates are generated at test time in a temp folder and never written to the repo.

- Strong: TLS 1.2 minimum, P-256 leaf with SHA-256 signed by a generated test CA, SAN for localhost and 127.0.0.1.
- Weak: every protocol and suite the local OpenSSL offers at security level 0, RSA 1024 key, SHA-1 signature, self-signed, 5 days to expiry. cryptography 50 will not sign with SHA-1, so the helper swaps the equal-length signature OID in the TBS bytes and signs them with the raw RSA key.

Results on this machine (Python 3.14.6, OpenSSL 3.5.7): the strong server gives zero violations. The weak server gives legacy_protocol for TLS 1.0 and 1.1, tls10_cbc, weak_cipher for NULL and anonymous suites, chain_invalid, expiring, weak_key, weak_signature and self_signed.

## Limits

- RC4, 3DES and EXPORT suites are not built into the local OpenSSL 3.5.7, so those probes report `untestable`. The weak server cannot offer them either, so no test covers an accepted RC4 or 3DES suite.
- TLS 1.0 and 1.1 worked locally at security level 0. On builds where they do not, the legacy protocol tests skip with a reason.
- Only the leaf certificate gets the key and signature checks. Intermediates are covered only by the chain check.
- No revocation, OCSP or certificate transparency checks.
- CBC suites under TLS 1.2 and curve choice are not flagged. Mozilla's intermediate profile does flag them.

## sslyze comparison

sslyze 6.1.0 ran in an isolated `uv tool run --python 3.12` environment against the same two local servers. Raw output is in `artifacts/sslyze/` (not committed).

| Item | assay | sslyze |
|---|---|---|
| Weak: TLS 1.0 and 1.1 | flagged | accepted, not compliant |
| Weak: NULL and anonymous suites | flagged | accepted (NULL, ECDH_anon), not compliant |
| Weak: RC4 | untestable | "Legacy RC4 Algorithm: Not Supported" |
| Weak: RSA 1024, SHA-1 | flagged | flagged |
| Weak: chain | chain_invalid | path validation failed |
| Strong: protocols | TLS 1.2 and 1.3 only | TLS 1.0 and 1.1 rejected |
| Strong: overall | 0 violations | not compliant with Mozilla intermediate: CBC SHA-256 suites on TLS 1.2 and extra curves |

The first sslyze run showed the weak server accepting anonymous ECDH suites, which our probe list missed. We added the anonymous probe after that run.
