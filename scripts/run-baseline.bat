@echo off
REM Run baseline scan (100+ images). If Go and Trivy are already in PATH you can run "go run ./cmd/baseline" from repo root without this script.
REM This script sets PATH from common locations so you don't need PATH set globally.
REM Results: test-results\baseline-YYYYMMDD-HHMMSS.csv (summary), baseline-*-findings.csv (full CVE/Title/Description/Exploitable/etc).
setlocal
cd /d "%~dp0.."
set "TRIVY_DIR=C:\Users\Master\Downloads\trivy_0.69.1_windows-64bit\Trivy"
set "GO_DIR=C:\Program Files\Go\bin"
if exist "%TRIVY_DIR%\trivy.exe" set "PATH=%TRIVY_DIR%;%PATH%"
if exist "%GO_DIR%\go.exe"     set "PATH=%GO_DIR%;%PATH%"
REM Use 1 worker to avoid Trivy cache lock; set BASELINE_WORKERS=5 if you want parallel (after closing other Trivy processes).
if not defined BASELINE_WORKERS set "BASELINE_WORKERS=1"
REM Rate-limit friendly run (10 random images, 10s between pulls): set BASELINE_LIMIT=10 BASELINE_RANDOM=1 BASELINE_DELAY_SEC=10 before running.

go run ./cmd/baseline
echo Results in test-results\
endlocal
