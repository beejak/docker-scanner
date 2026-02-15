# Remove Docker images that were scanned in a specific baseline run.
# Reads the baseline summary CSV and runs docker rmi on each image.
# Usage:
#   .\scripts\prune-baseline-run.ps1 -Csv test-results\baseline-20260215-235707.csv
#   .\scripts\prune-baseline-run.ps1  # uses latest baseline CSV in test-results

param(
    [string] $Csv
)

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Csv) {
    $testResults = Join-Path $repoRoot "test-results"
    if (-not (Test-Path $testResults)) {
        Write-Host "No test-results folder found. Specify -Csv path to a baseline summary CSV."
        exit 1
    }
    $latest = Get-ChildItem -Path $testResults -Filter "baseline-*-*.csv" | Where-Object { $_.Name -notmatch "findings" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) {
        Write-Host "No baseline summary CSV found in test-results. Specify -Csv path."
        exit 1
    }
    $Csv = $latest.FullName
    Write-Host "Using latest: $($latest.Name)"
}

if (-not (Test-Path $Csv)) {
    $Csv = Join-Path $repoRoot $Csv
}
if (-not (Test-Path $Csv)) {
    Write-Host "File not found: $Csv"
    exit 1
}

$lines = Get-Content $Csv
if ($lines.Count -lt 2) {
    Write-Host "CSV has no image rows."
    exit 0
}

$images = @()
for ($i = 1; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -match '^([^,]+),') {
        $images += $Matches[1].Trim()
    }
}

if ($images.Count -eq 0) {
    Write-Host "No images found in CSV."
    exit 0
}

$present = @()
foreach ($img in $images) {
    if (docker image inspect $img 2>$null) { $present += $img }
}
if ($present.Count -eq 0) {
    Write-Host "None of the $($images.Count) image(s) from the run are present (already removed)."
    exit 0
}
Write-Host "Removing $($present.Count) of $($images.Count) image(s) from baseline run..."
foreach ($img in $present) {
    docker rmi $img 2>&1
}
Write-Host "Done."
