@echo off
REM Run scanner locally (needs Go + Trivy in PATH). Use env-local.bat first if needed.
setlocal
cd /d "%~dp0.."
set "TRIVY_DIR=C:\Users\Master\Downloads\trivy_0.69.1_windows-64bit\Trivy"
set "GO_DIR=C:\Program Files\Go\bin"
if exist "%TRIVY_DIR%\trivy.exe" set "PATH=%TRIVY_DIR%;%PATH%"
if exist "%GO_DIR%\go.exe"     set "PATH=%GO_DIR%;%PATH%"

set IMAGE=%~1
if "%IMAGE%"=="" set IMAGE=alpine:latest
set REPORTS=%~dp0..\reports
mkdir "%REPORTS%" 2>nul

if exist scanner.exe (set SCAN=scanner.exe) else (set SCAN=go run ./cmd/cli)
%SCAN% scan --image %IMAGE% --output-dir "%REPORTS%" --format sarif,markdown,html
echo Reports in %REPORTS%
echo HTML report: %REPORTS%\report.html
if /i "%~2"=="/publish" call "%~dp0serve-report.bat"
endlocal
