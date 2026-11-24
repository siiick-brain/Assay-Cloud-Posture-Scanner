# Remediation tracking

`cspm.store.Store(path)` keeps the finding lifecycle in one SQLite file (stdlib `sqlite3`). Evidence, titles and resource IDs go through the same redactor as the reports before they are written. Each finding keeps its `id` from the unredacted identity, so the next scan finds it again.

## Lifecycle

| From | Event | To | verification_status |
|---|---|---|---|
| none | first scan that sees it | new | not_verified |
| new | next scan that sees it | open | not_verified |
| new, open, assigned, reopened | `assign(id, owner)` | assigned | unchanged |
| new, open, assigned, reopened | `claim_fixed(id)` | fixed_claimed | unchanged |
| any active state | rescan in scope no longer sees it | verified_closed | `verification_for(mode)` |
| fixed_claimed | rescan still sees it | reopened | not_verified |
| verified_closed | a later scan sees it again | reopened | not_verified |

Active states are new, open, assigned, fixed_claimed and reopened. A closure happens only inside `record_scan`, never by hand. An emulator or fixture rescan earns `verified`. A live rescan earns `observed_unverified`, never `verified`. A closure does not need a claim first: if a rescan stops seeing an issue, the issue is closed and the history note says whether a fix was claimed.

## Scope of a rescan

`ScanMeta.sources` (default assay) and `ScanMeta.providers` (default all) limit what a scan can close. A Trivy import cannot close assay findings and an Azure scan cannot close AWS findings. `ScanMeta.from_dict` takes the `scan` object of a findings report and uses its `providers` list.

## SLA due dates

| Band | Days from first seen |
|---|---|
| critical | 7 |
| high | 30 |
| medium | 90 |
| low | 180 |
| info | no due date |

A finding reopened after closure gets a fresh due date counted from the scan that saw it return. `overdue(now)` lists active findings past their date.

## History, diff and trend

Every transition is a row in `history` with the scan id (empty for manual steps), timestamp, from state, to state, verification status, actor and note. `observations` records what each scan saw.

- `diff(scan_a, scan_b)` backs `cspm diff`: added, removed and persisting finding ids plus band changes.
- `trend()` backs `cspm trend`: per scan the observed count, counts per band, new, closed, reopened and active findings after the scan.

## Demo

`uv run python scripts/demo_remediation.py --db artifacts/demo/remediation.db --claim-absent s0.json s1.json ...` records findings reports in order and prints each new, closed and reopened finding and a trend table. `--claim-absent` marks findings that vanish in the next report as fixed_claimed first, as an operator would after applying the fix. The script refuses to reuse an existing store.

Status: recorded. The insecure testbed was fixed in five Terraform steps against Moto, rescanned after each step and given one SSH regression. The output is in [demo/remediation-demo.md](demo/remediation-demo.md). Unit tests with synthetic finding sets are in tests/unit/test_store_demo.py.
