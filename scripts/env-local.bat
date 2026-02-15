@echo off
REM Add Trivy and Go to PATH for this window only. No admin or user variables needed.
REM Run this, then in the SAME window run: run-tests.bat or run-scan-local.bat
set "TRIVY_DIR=C:\Users\Master\Downloads\trivy_0.69.1_windows-64bit\Trivy"
set "GO_DIR=C:\Program Files\Go\bin"
if exist "%TRIVY_DIR%\trivy.exe" set "PATH=%TRIVY_DIR%;%PATH%"
if exist "%GO_DIR%\go.exe"     set "PATH=%GO_DIR%;%PATH%"
echo PATH updated for this window. Trivy and Go are available.
echo You can now run: run-tests.bat  or  run-scan-local.bat
cmd /k
REM To just set PATH and exit (e.g. for PowerShell): remove "cmd /k" above and use "call env-local.bat" before other commands.
