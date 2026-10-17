@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%Update-PrivescCheck.ps1"

if not exist "%PS1%" (
    echo.
    echo   Update-PrivescCheck.ps1 was not found next to this file:
    echo     %PS1%
    echo   Keep both files in the same folder.
    echo.
    pause
    exit /b 1
)

where powershell >nul 2>nul
if errorlevel 1 (
    echo.
    echo   powershell.exe was not found on PATH. Windows PowerShell 5.1 or later is required.
    echo.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"

echo.
pause
exit /b %RC%
