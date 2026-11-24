<#
.SYNOPSIS
Checks prose and code comments against the writing rules in docs/STYLE.md.
.EXAMPLE
pwsh scripts/check-style.ps1 docs README.md cspm
pwsh scripts/check-style.ps1 -CommitMessage "Add S3 rules"
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Path = @(),
    [string]$CommitMessage,
    [switch]$NoDefaultExcludes
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$banned = Get-Content (Join-Path $PSScriptRoot 'style-banned.txt') | Where-Object { $_.Trim() }
$emDash = [string][char]0x2014
# Files that quote the banned list on purpose.
$excludes = @('docs/STYLE.md', 'scripts/style-banned.txt', 'scripts/check-style.ps1', 'tests/style/')
$proseExt = @('.md', '.txt')
$codeExt = @('.py', '.ps1', '.sh', '.yaml', '.yml', '.toml', '.tf')
$script:problems = [System.Collections.Generic.List[string]]::new()

function Add-Problem([string]$where, [string]$what) { $script:problems.Add("${where}: $what") }

function Test-Prose([string]$text, [string]$where) {
    foreach ($phrase in $banned) {
        if ($text -match "(?i)\b$([regex]::Escape($phrase))\b") { Add-Problem $where "banned phrase '$phrase'" }
    }
    if ($text.Contains($emDash)) { Add-Problem $where 'em dash' }
    # Serial comma: "x, y, and z" where each item is a short run of words.
    if ($text -match '\b[\w-]+(?: [\w-]+){0,3}, [\w-]+(?: [\w-]+){0,3}, (?:and|or) \w') { Add-Problem $where 'comma before and/or in a list' }
}

function Get-Relative([string]$full) {
    [IO.Path]::GetRelativePath($root, $full).Replace('\', '/')
}

function Test-File([IO.FileInfo]$file) {
    $rel = Get-Relative $file.FullName
    if (-not $NoDefaultExcludes) {
        foreach ($e in $excludes) { if ($rel.StartsWith($e)) { return } }
    }
    $ext = $file.Extension.ToLowerInvariant()
    $lines = Get-Content -LiteralPath $file.FullName
    $inFence = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $where = "${rel}:$($i + 1)"
        if ($proseExt -contains $ext) {
            if ($line.TrimStart().StartsWith('```')) { $inFence = -not $inFence; continue }
            if ($inFence) { continue }
            Test-Prose ($line -replace '`[^`]*`', '') $where
        }
        elseif ($codeExt -contains $ext) {
            if ($line -match '\b(TODO|FIXME)\b') { Add-Problem $where 'TODO or FIXME' }
            if ($line -match '^\s*#(?!!)\s?(.*)$') { Test-Prose $Matches[1] $where }
        }
    }
}

if ($CommitMessage) {
    $title = ($CommitMessage -split "`n")[0]
    if ($title.Length -ge 72) { Add-Problem 'commit' 'title is 72 characters or more' }
    Test-Prose $CommitMessage 'commit'
}

foreach ($p in $Path) {
    $full = if ([IO.Path]::IsPathRooted($p)) { $p } else { Join-Path (Get-Location) $p }
    if (Test-Path -LiteralPath $full -PathType Container) {
        # Match on the path below $full so a checkout inside .worktrees/ still gets scanned.
        Get-ChildItem -LiteralPath $full -Recurse -File |
            Where-Object { [IO.Path]::GetRelativePath($full, $_.FullName) -notmatch '(^|[\\/])(\.git|\.venv|\.worktrees|node_modules|__pycache__|\.terraform)[\\/]' } |
            ForEach-Object { Test-File $_ }
    }
    elseif (Test-Path -LiteralPath $full) { Test-File (Get-Item -LiteralPath $full) }
    else { Add-Problem $p 'path not found' }
}

if ($script:problems.Count -gt 0) {
    $script:problems | ForEach-Object { Write-Output $_ }
    Write-Output "check-style: $($script:problems.Count) problem(s)"
    exit 1
}
Write-Output 'check-style: ok'
exit 0
