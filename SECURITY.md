# Security policy

Report a vulnerability through a private GitHub security advisory on this repository. Please do not open a public issue.

The scanner is read-only by design. A botocore hook blocks every AWS call that is not in cspm/live/allowlist.yaml. If you find a way around that hook, treat it as a vulnerability.

Tests and CI use the Moto emulator and synthetic fixtures. Never point the testbed at a real account.
