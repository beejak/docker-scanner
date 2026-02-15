@echo off
REM Run unit tests; if Trivy in PATH, run integration tests too.
REM No user PATH variable needed: uses Trivy/Go from known locations if present.
setlocal
cd /d "%~dp0.."
set "TRIVY_DIR=C:\Users\Master\Downloads\trivy_0.69.1_windows-64bit\Trivy"
set "GO_DIR=C:\Program Files\Go\bin"
if exist "%TRIVY_DIR%\trivy.exe" set "PATH=%TRIVY_DIR%;%PATH%"
if exist "%GO_DIR%\go.exe"     set "PATH=%GO_DIR%;%PATH%"

where go >nul 2>&1
if errorlevel 1 (
  echo Go not in PATH. Run scripts\setup-and-test.ps1 to install Go and run tests.
  exit /b 1
)
go test ./pkg/... -v -count=1
if errorlevel 1 exit /b 1
where trivy >nul 2>&1
if errorlevel 1 (
  echo Trivy not in PATH. Skipping integration tests. Run scripts\setup-and-test.ps1 to install Trivy.
  exit /b 0
)
go test -tags=integration ./tests/integration/... -v -count=1
endlocal
