<#
.SYNOPSIS
Lists every requirement ID from docs/requirements.md with the files that reference it.
.PARAMETER Strict
Exit 1 when any requirement has no reference outside docs/requirements.md.
#>
[CmdletBinding()]
param([switch]$Strict)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$reqFile = Join-Path $root 'docs/requirements.md'
$rows = Select-String -Path $reqFile -Pattern '^\| (REQ-[A-Z]-\d{3}) \| (.+?) \| (\d+) \| ([TIDA]) \|' |
    ForEach-Object { [pscustomobject]@{ Id = $_.Matches[0].Groups[1].Value; Item = $_.Matches[0].Groups[3].Value; Method = $_.Matches[0].Groups[4].Value } }

$skip = @('.git', '.venv', '.worktrees', 'artifacts', 'private', 'node_modules')
$files = @(Get-ChildItem -Path $root -File -Include *.py, *.md, *.ps1, *.yaml, *.yml, *.tf -Filter *) +
    @(Get-ChildItem -Path $root -Directory | Where-Object { $skip -notcontains $_.Name } |
        Get-ChildItem -Recurse -File -Include *.py, *.md, *.ps1, *.yaml, *.yml, *.tf)
$files = $files | Where-Object { $_ -and $_.FullName -ne $reqFile }

$missing = 0
foreach ($r in $rows) {
    $refs = $files | Select-String -SimpleMatch $r.Id -List | ForEach-Object { [IO.Path]::GetRelativePath($root, $_.Path).Replace('\', '/') }
    $refText = if ($refs) { ($refs | Sort-Object -Unique) -join ', ' } else { $missing++; '(none yet)' }
    '{0}  item {1,-2} {2}  {3}' -f $r.Id, $r.Item, $r.Method, $refText
}
"trace: $($rows.Count) requirements, $missing without references"
if ($Strict -and $missing -gt 0) { exit 1 }
exit 0
