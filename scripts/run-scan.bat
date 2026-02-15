@echo off
REM Run scanner via Docker (no local Go/Trivy needed)
setlocal
set IMAGE=%~1
if "%IMAGE%"=="" set IMAGE=alpine:latest
set REPORTS=%~dp0..\reports
mkdir "%REPORTS%" 2>nul
docker run --rm -v "%REPORTS%":/reports scanner:latest scan --image %IMAGE% --output-dir /reports --format sarif,markdown
echo Reports in %REPORTS%
endlocal
