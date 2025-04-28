@echo off
setlocal enabledelayedexpansion

set "APP_NAME=Falcon Identity Protection DC Sensor"
set "REG_KEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

:: Find registry entry with matching display name
for /f "tokens=*" %%a in ('reg query "%REG_KEY%" /s /f "%APP_NAME%" /d 2^>nul ^| findstr "HKEY_"') do (
    set "UNINSTALL_KEY=%%a"
)

:: If key found, get uninstall string and execute with quiet switch
if defined UNINSTALL_KEY (
    for /f "tokens=2,*" %%a in ('reg query "!UNINSTALL_KEY!" /v UninstallString 2^>nul') do (
        set "UNINSTALL_CMD=%%b"
    )
    
    if defined UNINSTALL_CMD (
        echo Uninstalling %APP_NAME%...
        start /wait !UNINSTALL_CMD! /qn
        echo Uninstallation completed successfully
        exit /b 0
    )
)

echo Failed to find uninstall information for %APP_NAME%
exit /b 1
