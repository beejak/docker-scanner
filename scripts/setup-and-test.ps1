# setup-and-test.ps1
# Install Go and Trivy (if missing), then run unit + integration tests.
# Run from repo root: .\scripts\setup-and-test.ps1
# Or: pwsh -ExecutionPolicy Bypass -File scripts\setup-and-test.ps1

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $RepoRoot "go.mod"))) {
    $RepoRoot = (Get-Location).Path
}
Set-Location $RepoRoot

function Refresh-Path {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

function Ensure-Go {
    Refresh-Path
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($go) {
        Write-Host "Go found: $($go.Source)"
        return $true
    }
    Write-Host "Go not in PATH. Attempting install via winget..."
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
        Write-Host "Go (portable) at $goBin"
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
    # Check common Windows locations (e.g. user extracted zip to Downloads)
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
    # Prefer Windows zip (fast); fall back to go install if zip fails
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
            Write-Host "Trivy (portable) at $($trivyExe.DirectoryName)"
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
    Write-Warning "Trivy not found. Unit tests will run; integration tests will be skipped."
    return $false
}

Write-Host "=== Setup and test (repo: $RepoRoot) ===" -ForegroundColor Cyan

if (-not (Ensure-Go)) { exit 1 }

Write-Host "`n--- go mod tidy ---" -ForegroundColor Cyan
& go mod tidy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n--- Build ---" -ForegroundColor Cyan
& go build -o scanner.exe ./cmd/cli
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Build OK." -ForegroundColor Green

Write-Host "`n--- Unit tests ---" -ForegroundColor Cyan
& go test ./pkg/... -v -count=1
$unitExit = $LASTEXITCODE
if ($unitExit -eq 0) { Write-Host "Unit tests OK." -ForegroundColor Green } else { Write-Host "Unit tests failed." -ForegroundColor Red }

$trivyOk = Ensure-Trivy
if ($trivyOk) {
    Write-Host "`n--- Integration tests ---" -ForegroundColor Cyan
    & go test -tags=integration ./tests/integration/... -v -count=1
    $intExit = $LASTEXITCODE
    if ($intExit -eq 0) { Write-Host "Integration tests OK." -ForegroundColor Green } else { Write-Host "Integration tests failed." -ForegroundColor Red }
    if ($unitExit -ne 0 -or $intExit -ne 0) { exit 1 }
} else {
    if ($unitExit -ne 0) { exit 1 }
}

Write-Host "`n=== All done. ===" -ForegroundColor Green
