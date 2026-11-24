# Handle a finding

A finding has two separate fields. `state` tracks the work. `verification_status` records how the closure was confirmed.

## States
| State | Who moves it | Meaning |
|---|---|---|
| new | scanner | First time this rule fired on this resource |
| open | triager | Accepted as real and not yet owned |
| assigned | triager | Has an owner and an SLA due date |
| fixed_claimed | owner | Owner says the fix is in |
| verified_closed | scanner | A rescan no longer shows it |
| reopened | scanner | The rescan still fails or the issue came back |

## Steps
1. Triage. Read the evidence and rationale in the report. Decide between real issue, accepted risk and false positive. A false positive is a rule bug, so open an issue against the rule with the evidence attached.
2. Assign an owner. The store sets the due date from the severity band.
3. Fix the resource. The remediation text in the finding is the starting point.
4. Mark it fixed_claimed once the change is deployed.
5. Rescan. Only the scanner moves a finding to verified_closed. An emulator or fixture rescan earns `verified`. A live rescan earns `observed_unverified`. Without a rescan it stays `not_verified`.
6. If the rescan still shows the issue, the finding goes to reopened and back to the owner.

## Accepted risk
Write down who accepted it, why and until when. Keep the finding open so it stays visible in `cspm trend`.

## Findings from other tools
Trivy, Prowler, Checkov and OpenSCAP findings carry their own `source`. They follow the same states, and only a rescan with the same tool verifies the closure.
