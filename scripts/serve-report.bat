@echo off
REM Publish/serve the scan report so you can view it in the browser.
REM Run after a scan (reports in repo\reports). Serves on http://localhost:8080 or opens report file.
setlocal
cd /d "%~dp0.."
set "REPORTS=%~dp0..\reports"
set "PORT=8080"

if not exist "%REPORTS%\report.html" (
  echo No report found at %REPORTS%\report.html
  echo Run a scan first: scripts\run-scan-local.bat
  exit /b 1
)

REM Prefer serving via HTTP so links and assets work; fallback: open file in browser
where python >nul 2>&1
if errorlevel 1 goto openfile

echo Serving reports at http://localhost:%PORT%
echo Open http://localhost:%PORT%/reports/report.html in your browser.
echo Press Ctrl+C to stop.
start "" "http://localhost:%PORT%/reports/report.html"
cd /d "%~dp0.."
python -m http.server %PORT%
goto :eof

:openfile
echo Opening report in default browser...
start "" "%REPORTS%\report.html"
echo Report opened. Location: %REPORTS%\report.html
endlocal
exit /b 0
