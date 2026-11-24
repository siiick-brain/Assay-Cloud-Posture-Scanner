<#
.SYNOPSIS
Checks README and docs images: every referenced image exists, size limits hold and OCR finds no private strings.
.DESCRIPTION
Size limits: each GIF at most 5 MB, each PNG under 1.5 MB. OCR uses Tesseract and, for GIF frames and upscaling, ffmpeg.
When Tesseract is missing the OCR step is reported as SKIPPED with the reason, never as passed.
.EXAMPLE
pwsh -NoProfile -File scripts/check-readme-images.ps1
pwsh -NoProfile -File scripts/check-readme-images.ps1 -RequireOcr
#>
[CmdletBinding()]
param(
    [switch]$RequireOcr
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$failures = [System.Collections.Generic.List[string]]::new()
$gifMax = 5MB
$pngMax = 1.5MB
# Literal strings and patterns that must never show up in an image.
$forbidden = @(
    @{ Name = 'Users\'; Regex = 'Users\\' },
    @{ Name = 'Davis'; Regex = '(?i)Davis' },
    @{ Name = '12-digit number'; Regex = '(?<!\d)\d{12}(?!\d)' },
    @{ Name = 'AKIA'; Regex = 'AKIA' }
)

function Get-Tool([string]$name, [string[]]$extra) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in $extra) { if ($p -and (Test-Path $p)) { return $p } }
    return $null
}

$mdFiles = @()
$readme = Join-Path $root 'README.md'
if (Test-Path $readme) { $mdFiles += Get-Item $readme }
$mdFiles += Get-ChildItem (Join-Path $root 'docs') -Filter *.md -Recurse -File

$referenced = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$refPattern = '!\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)|<img\s[^>]*src\s*=\s*"([^"]+)"'
foreach ($md in $mdFiles) {
    $rel = [IO.Path]::GetRelativePath($root, $md.FullName)
    $text = Get-Content $md.FullName -Raw
    foreach ($m in [regex]::Matches($text, $refPattern)) {
        $target = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        if ($target -match '^(https?:|data:|#)') { continue }
        $target = ($target -split '[?#]')[0]
        $path = [IO.Path]::GetFullPath((Join-Path $md.DirectoryName ([Uri]::UnescapeDataString($target))))
        if (Test-Path $path -PathType Leaf) {
            [void]$referenced.Add($path)
        } else {
            $failures.Add("missing image: $target (referenced in $rel)")
        }
    }
}
Write-Host "references: $($referenced.Count) existing image(s) referenced from $($mdFiles.Count) Markdown file(s)"

$images = @($referenced)
$imgDir = Join-Path $root 'docs/images'
if (Test-Path $imgDir) {
    $images += Get-ChildItem $imgDir -File | Where-Object { $_.Extension -in '.png', '.gif' } | ForEach-Object { $_.FullName }
}
$images = $images | Sort-Object -Unique

foreach ($img in $images) {
    $rel = [IO.Path]::GetRelativePath($root, $img)
    $size = (Get-Item $img).Length
    $ext = [IO.Path]::GetExtension($img).ToLowerInvariant()
    if ($ext -eq '.gif' -and $size -gt $gifMax) { $failures.Add("$rel is $size bytes, over 5 MB") }
    if ($ext -eq '.png' -and $size -ge $pngMax) { $failures.Add("$rel is $size bytes, not under 1.5 MB") }
    Write-Host ("size: {0,-40} {1,10:N0} bytes" -f $rel, $size)
}

$links = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links'
$tesseract = Get-Tool 'tesseract' @('C:\Program Files\Tesseract-OCR\tesseract.exe', "$env:LOCALAPPDATA\Programs\Tesseract-OCR\tesseract.exe")
$ffmpeg = Get-Tool 'ffmpeg' @((Join-Path $links 'ffmpeg.exe'))
$ocrStatus = $null

if (-not $tesseract) {
    $ocrStatus = 'SKIPPED: tesseract not found on PATH or in the default install folders'
} elseif (-not $images) {
    $ocrStatus = 'SKIPPED: no images to read'
} else {
    $work = Join-Path ([IO.Path]::GetTempPath()) ("readme-ocr-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $work | Out-Null
    $skippedGifs = @()
    try {
        foreach ($img in $images) {
            $rel = [IO.Path]::GetRelativePath($root, $img)
            $name = [IO.Path]::GetFileNameWithoutExtension($img)
            $ext = [IO.Path]::GetExtension($img).ToLowerInvariant()
            $pages = @()
            if ($ffmpeg) {
                # Upscaling helps Tesseract read small terminal text. mpdecimate drops repeated GIF frames, so each step is read once.
                & $ffmpeg -v error -y -i $img -vf 'mpdecimate,scale=iw*2:-1:flags=lanczos' -fps_mode vfr (Join-Path $work "$name-%03d.png")
                if ($LASTEXITCODE -ne 0) { $failures.Add("ffmpeg could not read $rel"); continue }
                $pages = Get-ChildItem $work -Filter "$name-*.png" | ForEach-Object { $_.FullName }
            } elseif ($ext -eq '.gif') {
                $skippedGifs += $rel
                continue
            } else {
                $pages = @($img)
            }
            $text = foreach ($page in $pages) { & $tesseract $page stdout 2>$null }
            $text = $text -join "`n"
            foreach ($f in $forbidden) {
                if ($text -match $f.Regex) { $failures.Add("OCR found '$($f.Name)' in $rel ('$($Matches[0])')") }
            }
            Write-Host ("ocr:  {0,-40} {1} page(s), {2} chars read" -f $rel, $pages.Count, $text.Length)
        }
    } finally {
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    }
    $version = (& $tesseract --version 2>&1 | Select-Object -First 1)
    $ocrStatus = if ($skippedGifs) { "PARTIAL: $version; GIFs not read without ffmpeg: $($skippedGifs -join ', ')" } else { "RAN: $version" }
}

foreach ($f in $failures) { Write-Host "FAIL $f" }
Write-Host "OCR $ocrStatus"
if ($failures.Count) {
    Write-Host "RESULT: FAILED ($($failures.Count) problem(s))"
    exit 1
}
if ($ocrStatus -like 'RAN*') {
    Write-Host 'RESULT: PASSED (references, sizes and OCR)'
    exit 0
}
Write-Host "RESULT: references and sizes passed; OCR not passed ($ocrStatus)"
if ($RequireOcr) { exit 1 }
exit 0
