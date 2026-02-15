# Update Trivy vulnerability database (run daily for fresh CVE data).
# Run from repo root: .\scripts\update-trivy-db.ps1
# Schedule daily: Task Scheduler - create a daily task that runs: powershell -File "C:\path\to\docker-scanner\scripts\update-trivy-db.ps1"

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $RepoRoot "go.mod"))) { $RepoRoot = (Get-Location).Path }
Set-Location $RepoRoot

$CacheDir = if ($env:TRIVY_CACHE_DIR) { $env:TRIVY_CACHE_DIR } else { Join-Path $RepoRoot ".trivy\cache" }
New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
$env:TRIVY_CACHE_DIR = $CacheDir

$trivy = Get-Command trivy -ErrorAction SilentlyContinue
if (-not $trivy) {
    Write-Error "Trivy not in PATH. Run scripts\install-deps.ps1 first or add Trivy to PATH."
    exit 1
}

Write-Host "$(Get-Date -Format 'o') Updating Trivy DB..."
& trivy image --download-db-only --cache-dir $CacheDir
Write-Host "$(Get-Date -Format 'o') Trivy DB update done."
