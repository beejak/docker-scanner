# Install dependencies for Docker Container Scanner on Windows.
# Run from repo root: .\scripts\install-deps.ps1  (runs in background by default)
# To run in foreground (wait for completion): .\scripts\install-deps.ps1 -Foreground
# Installs: Go 1.21+, Trivy. Optional: Docker (install separately if you want to use the scanner image).

param([switch] $Foreground)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $RepoRoot "go.mod"))) { $RepoRoot = (Get-Location).Path }
$LogFile = Join-Path $RepoRoot "install-deps.log"

if (-not $Foreground) {
    Write-Host "Starting dependency installation in the background. Log: $LogFile"
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Foreground" -RedirectStandardOutput $LogFile -RedirectStandardError $LogFile -WindowStyle Hidden
    Write-Host "Run 'Get-Content $LogFile -Wait' to watch progress, or re-run with -Foreground to run in this window."
    exit 0
}

Set-Location $RepoRoot

function Refresh-Path {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

function Ensure-Go {
    Refresh-Path
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($go) {
        $ver = (go version 2>$null) -replace '.*go(\d+\.\d+).*','$1'
        if ($ver -and [version]$ver -ge [version]"1.21") {
            Write-Host "Go found: $($go.Source)"
            return $true
        }
    }
    Write-Host "Go not in PATH or version < 1.21. Attempting install via winget..."
    try {
        winget install -e --id GoLang.Go --accept-package-agreements --accept-source-agreements 2>&1
        Refresh-Path
        $go = Get-Command go -ErrorAction SilentlyContinue
        if ($go) {
            Write-Host "Go installed: $($go.Source)"
            return $true
        }
    } catch {
        Write-Warning "winget install failed: $_"
    }
    Write-Host "Trying portable Go download..."
    $goZip = "https://go.dev/dl/go1.21.13.windows-amd64.zip"
    $extractTo = Join-Path $RepoRoot ".go"
    $goDir = Join-Path $extractTo "go"
    if (-not (Test-Path (Join-Path $goDir "bin\go.exe"))) {
        New-Item -ItemType Directory -Force -Path $extractTo | Out-Null
        $zipPath = Join-Path $env:TEMP "go.zip"
        Invoke-WebRequest -Uri $goZip -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $extractTo -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    }
    $goBin = Join-Path $goDir "bin"
    if (Test-Path (Join-Path $goBin "go.exe")) {
        $env:Path = "$goBin;$env:Path"
        Write-Host "Go (portable) at $goBin. Add to PATH for new shells: `$env:Path = `"$goBin`";`$env:Path"
        return $true
    }
    Write-Error "Could not install Go. Install manually: https://go.dev/dl/"
    return $false
}

function Ensure-Trivy {
    Refresh-Path
    $trivy = Get-Command trivy -ErrorAction SilentlyContinue
    if ($trivy) {
        Write-Host "Trivy found: $($trivy.Source)"
        return $true
    }
    $commonPaths = @(
        (Join-Path $env:USERPROFILE "Downloads\trivy_0.69.1_windows-64bit\Trivy"),
        (Join-Path $env:USERPROFILE "Downloads\trivy_*\Trivy")
    )
    foreach ($p in $commonPaths) {
        $dir = $null
        if ($p -match '\*') { $dir = Get-Item $p -ErrorAction SilentlyContinue | Select-Object -First 1 }
        else { $dir = Get-Item $p -ErrorAction SilentlyContinue }
        if ($dir -and (Test-Path (Join-Path $dir.FullName "trivy.exe"))) {
            $env:Path = "$($dir.FullName);$env:Path"
            Write-Host "Trivy found at: $($dir.FullName)"
            return $true
        }
    }
    Write-Host "Downloading Trivy Windows binary..."
    $trivyVersion = "v0.69.1"
    $zipUrl = "https://github.com/aquasecurity/trivy/releases/download/$trivyVersion/trivy_0.69.1_Windows-64bit.zip"
    $extractTo = Join-Path $RepoRoot ".trivy"
    $zipPath = Join-Path $env:TEMP "trivy_$([Guid]::NewGuid().ToString('N')).zip"
    try {
        $trivyExe = Get-ChildItem -Path $extractTo -Recurse -Filter "trivy.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $trivyExe) {
            New-Item -ItemType Directory -Force -Path $extractTo | Out-Null
            Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath $extractTo -Force
            $trivyExe = Get-ChildItem -Path $extractTo -Recurse -Filter "trivy.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        if ($trivyExe) {
            $env:Path = "$($trivyExe.DirectoryName);$env:Path"
            Write-Host "Trivy (portable) at $($trivyExe.DirectoryName). Add to PATH for new shells if needed."
            return $true
        }
    } catch {
        Write-Warning "Trivy zip download failed: $_"
    } finally {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    }
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($go) {
        Write-Host "Installing Trivy via go install (may take a few minutes)..."
        $env:GOPATH = if ($env:GOPATH) { $env:GOPATH } else { Join-Path $env:USERPROFILE "go" }
        $gobin = Join-Path $env:GOPATH "bin"
        cmd /c "go install github.com/aquasecurity/trivy/cmd/trivy@latest 2>nul"
        if (Test-Path (Join-Path $gobin "trivy.exe")) {
            $env:Path = "$gobin;$env:Path"
            Write-Host "Trivy installed at $gobin"
            return $true
        }
    }
    Write-Error "Could not install Trivy. Install manually: https://github.com/aquasecurity/trivy#installation"
    return $false
}

Write-Host "=== Install dependencies (repo: $RepoRoot) ===" -ForegroundColor Cyan

if (-not (Ensure-Go)) { exit 1 }
Write-Host ""
if (-not (Ensure-Trivy)) { exit 1 }

Write-Host "`n--- go mod tidy ---" -ForegroundColor Cyan
& go mod tidy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Done. You can now build and run ===" -ForegroundColor Green
Write-Host "  go build -o scanner.exe ./cmd/cli"
Write-Host "  .\scanner.exe scan --image alpine:latest --output-dir ./reports"
Write-Host "Optional: Install Docker to use the scanner as a container (docker build -t scanner:latest .)."
