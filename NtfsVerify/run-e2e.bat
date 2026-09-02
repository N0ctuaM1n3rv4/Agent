@echo off
setlocal enabledelayedexpansion

:: NtfsVerify end-to-end driver. Must run as Administrator.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script must be run as Administrator.
    echo     Right-click Command Prompt and choose "Run as administrator".
    exit /b 3
)

cd /d "%~dp0"

echo [*] Building NtfsVerify ...
dotnet build ..\agents.sln -c Debug --no-restore 2>&1
if %errorlevel% neq 0 (
    echo [!] Build failed.
    exit /b 1
)

echo [*] Running NtfsVerify VHD e2e ...
".\bin\Debug\net8.0\NtfsVerify.exe" %*
set result=%errorlevel%

if %result% equ 0 (
    echo [+] E2E passed.
) else (
    echo [!] E2E failed with exit code %result%.
)
exit /b %result%
