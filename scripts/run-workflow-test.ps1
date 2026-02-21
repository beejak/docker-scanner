# Workflow test: pull a few old and new images from different registries, then scan each with config.
# Uses tests/baseline/images-workflow-test.txt and scanner.yaml (created from scanner.yaml.example if missing).
# From repo root: .\scripts\run-workflow-test.ps1
# Optional: -PullFirst to docker pull each image before scanning (recommended for "even distribution" test).

param(
    [switch]$PullFirst = $false
)

$ErrorActionPreference = "Stop"

# Add Trivy and Go to PATH if not already there (same locations as run-scan-local.bat / run-tests.bat).
# Edit these paths if your install locations differ.
$trivyDir = "C:\Users\Master\Downloads\trivy_0.69.1_windows-64bit\Trivy"
$goDir = "C:\Program Files\Go\bin"
if (-not (Get-Command trivy -ErrorAction SilentlyContinue)) {
    if (Test-Path "$trivyDir\trivy.exe") { $env:PATH = "$trivyDir;$env:PATH" }
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    if (Test-Path "$goDir\go.exe") { $env:PATH = "$goDir;$env:PATH" }
}

$listPath = "tests/baseline/images-workflow-test.txt"
$configExample = "scanner.yaml.example"
$configPath = "scanner.yaml"

if (-not (Test-Path $listPath)) {
    Write-Error "Image list not found: $listPath. Run from repo root."
}
$images = Get-Content $listPath | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }

# Ensure scanner.yaml exists
if (-not (Test-Path $configPath) -and (Test-Path $configExample)) {
    Copy-Item $configExample $configPath
    Write-Host "Created $configPath from $configExample"
}

# Build scanner if needed
$scanner = "scanner.exe"
if (-not (Get-Command $scanner -ErrorAction SilentlyContinue)) {
    if (Test-Path "scanner.exe") { $scanner = ".\scanner.exe" }
    elseif (Get-Command "go" -ErrorAction SilentlyContinue) {
        Write-Host "Building scanner..."
        go build -o scanner.exe ./cmd/cli
        $scanner = ".\scanner.exe"
    } else {
        Write-Error "No scanner binary and go not in PATH. Build with: go build -o scanner.exe ./cmd/cli"
    }
}

$reportsDir = "reports"
if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }

Write-Host "Workflow test: $($images.Count) images from multiple registries (config + scan)"
if ($PullFirst) {
    Write-Host "Pulling images first..."
    foreach ($img in $images) {
        docker pull $img
        if ($LASTEXITCODE -ne 0) { Write-Warning "Pull failed: $img" }
    }
}

$ok = 0
$fail = 0
$total = $images.Count
$i = 0
foreach ($img in $images) {
    $i++
    $safe = $img -replace '[/:]', '-'
    $outName = "wf-$safe"
    # Progress TUI: one updating line per image
    $msg = "[ $i/$total ] Scanning $img ..."
    Write-Host -NoNewline "`r$msg"
    $out = & $scanner scan --image $img --output-dir $reportsDir --output-name $outName --format markdown,html 2>&1
    if ($LASTEXITCODE -eq 0) {
        $ok++
        $findings = if ($out -match "(\d+) findings") { $Matches[1] } else { "?" }
        Write-Host "`r[ $i/$total ] $img done ($findings findings)   "
    } else {
        $fail++
        Write-Host "`r[ $i/$total ] $img FAILED   "
    }
}

Write-Host "`nDone. OK=$ok FAIL=$fail. Reports in $reportsDir (wf-*.md, wf-*.html)"
