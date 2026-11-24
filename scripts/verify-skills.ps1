<#
.SYNOPSIS
Checks every proof path in docs/skills-evidence.md and runs the 24 gate rows from docs/spec.md.
.PARAMETER Strict
Exit 1 when any proof path is missing or any gate fails. Gates that need a push or a tool that is absent count as Not verified, not as failed.
.PARAMETER SkipTests
Reuse artifacts/gates/pytest-cov.txt instead of running pytest again.
#>
[CmdletBinding()]
param([switch]$Strict, [switch]$SkipTests)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
$py = if (Test-Path '.venv/Scripts/python.exe') { '.venv/Scripts/python.exe' } else { '.venv/bin/python' }
$rows = [System.Collections.Generic.List[object]]::new()

function Add-Row([string]$gate, [string]$check, [string]$status, [string]$detail) {
    $rows.Add([pscustomobject]@{ Gate = $gate; Check = $check; Status = $status; Detail = $detail })
}

function Test-Cmd([string]$gate, [string]$check, [scriptblock]$cmd, [string]$okPattern) {
    $out = (& $cmd 2>&1 | Out-String)
    $ok = ($LASTEXITCODE -eq 0) -and (-not $okPattern -or $out -match $okPattern)
    $last = ($out.Trim() -split "`n")[-1].Trim()
    Add-Row $gate $check ($(if ($ok) { 'Met' } else { 'Missed' })) $last
}

# Proof paths in the skills table.
$missing = @()
foreach ($line in Get-Content 'docs/skills-evidence.md') {
    if ($line -notmatch '^\| (?!Skill|---)(.+?) \| \d+ \| (.+?) \| (.+?) \|$') { continue }
    foreach ($p in ($Matches[2] -split ';')) {
        $p = $p.Trim()
        if ($p -and -not (Test-Path $p)) { $missing += "$($Matches[1]): $p" }
    }
}

Test-Cmd 'G01' 'ruff' { & $py -m ruff check . --output-format concise } 'All checks passed'
Test-Cmd 'G02' 'mypy strict' { & $py -m mypy } 'Success'
if ($SkipTests -and (Test-Path 'artifacts/gates/pytest-cov.txt')) {
    $cov = Get-Content 'artifacts/gates/pytest-cov.txt' -Raw
} else {
    $cov = (& $py -m pytest -q --tb=line -m 'not emulator and not docker' --cov --cov-report=term 2>&1 | Out-String)
    New-Item -ItemType Directory -Force 'artifacts/gates' | Out-Null
    Set-Content 'artifacts/gates/pytest-cov.txt' $cov
}
$failed = $cov -match '\d+ failed'
Add-Row 'G03' 'pytest' ($(if ($failed) { 'Missed' } else { 'Met' })) ($(if ($failed) { 'failures present' } else { 'no failures' }))
$pct = if ($cov -match 'Total coverage: ([\d.]+)%') { [double]$Matches[1] } else { 0 }
Add-Row 'G04' 'coverage >= 85' ($(if ($pct -ge 85) { 'Met' } else { 'Missed' })) "$pct percent"

$counts = & $py -c @'
from collections import defaultdict
from pathlib import Path
from cspm.contracts import RULE_IDS
from cspm.mapping import load_frameworks
fam = defaultdict(set)
for f in load_frameworks():
    for row in getattr(f, "rows", getattr(f, "mappings", [])):
        fam[getattr(row, "rule_id", None) or row[0]].add(f.family)
tests = Path("tests/unit/test_rules_cases.py").read_text(encoding="utf-8")
print(len(RULE_IDS), min(len(fam[r.id]) for r in RULE_IDS), sum(r.id in tests for r in RULE_IDS))
'@
$n, $minFam, $tested = ($counts -split ' ') | ForEach-Object { [int]$_ }
Add-Row 'G05' 'rule count >= 25' ($(if ($n -ge 25) { 'Met' } else { 'Missed' })) "$n rules"
Add-Row 'G06' 'positive and negative test per rule' ($(if ($tested -eq $n) { 'Met' } else { 'Missed' })) "$tested of $n rule IDs in test_rules_cases.py"
Test-Cmd 'G07-G09' 'recall, secure zero, exact count' { & $py -m pytest -q tests/integration/test_recall.py -p no:cacheprovider } ''
$bench = 'artifacts/bench/scan-time.md'
Add-Row 'G10' 'scan under 60 s' ($(if ((Test-Path $bench) -and ((Get-Content $bench -Raw) -match 'Met')) { 'Met' } else { 'Not verified' })) $bench
Test-Cmd 'G11' 'reports validate' { & $py -m pytest -q tests/unit/test_reports.py tests/contracts -p no:cacheprovider } ''
Add-Row 'G12' 'frameworks per rule >= 3' ($(if ($minFam -ge 3) { 'Met' } else { 'Missed' })) "minimum $minFam families"
Test-Cmd 'G13' 'identifiers exist locally' { & $py -m pytest -q tests/unit/test_mapping.py -p no:cacheprovider } ''
Test-Cmd 'G14' 'write block test' { & $py -m pytest -q tests/unit/test_collectors_guard.py -p no:cacheprovider } ''
Test-Cmd 'G15' 'static allowlist check' { & $py scripts/check_allowlist.py } 'ok'
if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
    $leaks = 0
    foreach ($target in @(@('git', '.'), @('dir', 'private'), @('dir', 'artifacts'))) {
        if ($target[1] -ne '.' -and -not (Test-Path $target[1])) { continue }
        & gitleaks $target[0] --no-banner --redact $target[1] *> $null
        if ($LASTEXITCODE -ne 0) { $leaks++ }
    }
    Add-Row 'G16' 'gitleaks repo, private, artifacts' ($(if ($leaks -eq 0) { 'Met' } else { 'Missed' })) "$leaks target(s) with leaks"
} else { Add-Row 'G16' 'gitleaks' 'Not verified' 'gitleaks not installed' }
Test-Cmd 'G17' 'style check' { pwsh -NoProfile -File scripts/check-style.ps1 docs README.md CHANGELOG.md cspm rules scripts .github } 'ok'
$unpinned = Select-String -Path '.github/workflows/*.yml' -Pattern '^\s*-?\s*uses:\s*(?!\./)[^@\s]+@(?![0-9a-f]{40}\b)' | Measure-Object | Select-Object -ExpandProperty Count
Add-Row 'G18' 'actions pinned by SHA' ($(if ($unpinned -eq 0) { 'Met' } else { 'Missed' })) "$unpinned unpinned"
if (Get-Command actionlint -ErrorAction SilentlyContinue) { Test-Cmd 'G19' 'actionlint' { actionlint } '' } else { Add-Row 'G19' 'actionlint' 'Not verified' 'actionlint not installed' }
$rec = @('fixtures/recorded/trivy', 'fixtures/recorded/prowler') | Where-Object { -not (Test-Path $_) }
Add-Row 'G20' 'Trivy and Prowler recorded' ($(if (-not $rec) { 'Met' } else { 'Missed' })) 'fixtures/recorded/'
Add-Row 'G21' 'OpenSCAP before and after' ($(if ((Get-Content 'docs/hardening.md' -Raw) -match '129') { 'Met' } else { 'Missed' })) 'docs/hardening.md'
Add-Row 'G22' 'demo with regression' ($(if ((Test-Path 'docs/demo/remediation-demo.md') -and ((Get-Content 'docs/demo/remediation-demo.md' -Raw) -match 'reopened')) { 'Met' } else { 'Missed' })) 'docs/demo/remediation-demo.md'
if (Test-Path 'scripts/check-readme-images.ps1') {
    $img = (pwsh -NoProfile -File scripts/check-readme-images.ps1 2>&1 | Out-String)
    $st = if ($LASTEXITCODE -ne 0) { 'Missed' } elseif ($img -match '(?i)skipped') { 'Not verified' } else { 'Met' }
    Add-Row 'G23' 'README images' $st (($img.Trim() -split "`n")[-1].Trim())
} else { Add-Row 'G23' 'README images' 'Missed' 'scripts/check-readme-images.ps1 missing' }
Add-Row 'G24' 'skill claims have proof' ($(if (-not $missing) { 'Met' } else { 'Missed' })) "$($missing.Count) missing proof path(s)"

$report = @('# Skills and gate report', '', "Generated by scripts/verify-skills.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm').", '', '| Gate | Check | Status | Detail |', '|---|---|---|---|')
$report += $rows | ForEach-Object { "| $($_.Gate) | $($_.Check) | $($_.Status) | $($_.Detail -replace '\|', '/') |" }
if ($missing) { $report += @('', '## Missing proof paths') + ($missing | ForEach-Object { "- $_" }) }
New-Item -ItemType Directory -Force 'artifacts' | Out-Null
Set-Content 'artifacts/skills-report.md' $report
$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
Pop-Location

$bad = @($rows | Where-Object Status -eq 'Missed').Count + $missing.Count
Write-Output "verify-skills: $(@($rows | Where-Object Status -eq 'Met').Count) Met, $(@($rows | Where-Object Status -eq 'Not verified').Count) Not verified, $bad problem(s)"
if ($Strict -and $bad -gt 0) { exit 1 }
exit 0
