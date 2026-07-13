# Fetch bet365.com with C++ --auto-challenge-scripts and summarize results.
param(
    [string]$Exe = "",
    [string]$Url = "https://www.bet365.com"
)

$ErrorActionPreference = "Continue"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir = Join-Path (Join-Path $RepoRoot "builds") "test_bet365_${Stamp}"

if (-not $Exe) {
    if ($env:BW_FETCHER_EXE -and (Test-Path $env:BW_FETCHER_EXE)) {
        $Exe = $env:BW_FETCHER_EXE
    } elseif (Test-Path (Join-Path $RepoRoot "builds" "latest_windows.txt")) {
        $Bd = (Get-Content (Join-Path $RepoRoot "builds" "latest_windows.txt") -Raw).Trim()
        $Exe = Join-Path $Bd "BW-Fetcher-win64.exe"
    } else {
        throw "Set -Exe or run scripts/build_cpp_windows.ps1 first"
    }
}

New-Item -ItemType Directory -Force -Path "$OutDir\also" | Out-Null
$PageOut = Join-Path $OutDir "page.bin"
$AlsoDir = Join-Path $OutDir "also"

Write-Host "==> URL:  $Url"
Write-Host "==> Exe:  $Exe"
Write-Host "==> Out:  $OutDir"
Write-Host ""

$raw = cmd.exe /c "`"$Exe`" --url $Url --out `"$PageOut`" --auto-challenge-scripts --max-challenge-scripts 10 --also-out-dir `"$AlsoDir`" --timeout 90000 2>&1"
$exit = $LASTEXITCODE
$jsonLine = ($raw | Where-Object { $_ -match '^\{' }) | Select-Object -Last 1

if ($exit -ne 0 -or -not $jsonLine) {
    Write-Host $raw
    exit 1
}

$summary = $jsonLine | ConvertFrom-Json
Write-Host "--- Primary ---"
Write-Host "status: $($summary.status)  bytes: $($summary.bytes)  url: $($summary.url)"
Write-Host "cf-ray: $($summary.headers.'cf-ray')"
Write-Host ""

$html = [System.Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($PageOut))
$srcMatches = [regex]::Matches($html, '<script[^>]+src\s*=\s*["'']([^"'']+)["'']', 'IgnoreCase')
Write-Host "--- script src in HTML ($($srcMatches.Count)) ---"
foreach ($m in $srcMatches) { Write-Host "  $($m.Groups[1].Value)" }
if ($srcMatches.Count -eq 0) { Write-Host "  (none)" }

$inline = [regex]::Matches($html, '<script(?![^>]*\bsrc\b)[^>]*>([\s\S]{0,300}?)<\/script>', 'IgnoreCase')
Write-Host ""
Write-Host "--- inline script previews ($($inline.Count)) ---"
$i = 0
foreach ($m in $inline) {
    if ($i -ge 5) { Write-Host "  ..."; break }
    $t = ($m.Groups[1].Value -replace '\s+', ' ').Trim()
    if ($t.Length -gt 100) { $t = $t.Substring(0, 100) + "..." }
    Write-Host "  [$i] $t"
    $i++
}

Write-Host ""
Write-Host "--- Challenge scripts fetched ---"
if ($summary.subresources -and @($summary.subresources).Count -gt 0) {
    $j = 0
    foreach ($sub in $summary.subresources) {
        $path = Join-Path $AlsoDir "also_$j.bin"
        Write-Host "[$j] $($sub.url)  status=$($sub.status) bytes=$($sub.bytes)"
        if (Test-Path $path) {
            $bytes = [IO.File]::ReadAllBytes($path)
            $preview = [System.Text.Encoding]::UTF8.GetString($bytes[0..([Math]::Min(199, $bytes.Length - 1))])
            $preview = ($preview -replace '\s+', ' ').Trim()
            if ($preview.Length -gt 120) { $preview = $preview.Substring(0, 120) + "..." }
            Write-Host "     $preview"
        }
        $j++
    }
} else {
    Write-Host '  (none - no challenge script URLs matched in HTML; Cloudflare may inject JS dynamically)'
}

Write-Host ""
Write-Host "Artifacts: $OutDir"
