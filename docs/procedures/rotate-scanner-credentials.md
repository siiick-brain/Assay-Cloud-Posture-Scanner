# Rotate scanner credentials

The scanner only needs credentials in live mode. CI never holds cloud credentials, so there is nothing to rotate there.

## What the scanner should hold
- A role session from `aws sts assume-role` or IAM Identity Center, valid for one hour or less.
- The role has SecurityAudit and ViewOnlyAccess only.
- Credentials live in environment variables of the one shell that runs the scan. Never in files and never in the repo.

## Routine rotation
Short sessions expire on their own. Start each live scan with a fresh session and close the shell afterwards.

## If a static access key was used
Static keys are not the intended setup. If one exists anyway:
1. Create a second key for the scanner user.
2. Switch the scan shell to the new key and run one scan to check it works.
3. Deactivate the old key and wait a day for anything still using it to show up in CloudTrail.
4. Delete the old key.
5. Move to role sessions so this procedure is no longer needed.

## If credentials may have leaked
1. Revoke active sessions for the role or deactivate the key at once.
2. Check CloudTrail for calls from the scanner identity that are not Describe, List or Get.
3. Run gitleaks on the repo, private/ and artifacts/: `gitleaks dir . --redact`.
4. Record what happened, what was exposed and the fix in a private incident note.

The allowlist hook does not help once someone else holds the keys. Short session lifetimes and the read-only role limit the damage in that case.
