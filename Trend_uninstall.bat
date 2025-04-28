@echo off

REM Extract the zip file
7za.exe x "DSA_CUT.zip" -o"C:\temp" -r -y

REM Change directory to temp
cd /D "C:\temp"

REM Run the initial cleanup command
"DSA_CUT.exe" -c

REM Check if ds_agent service exists
sc query ds_agent >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo ds_agent service is present. Running force uninstall.
    
    REM Run the force uninstall command
    "DSA_CUT.exe" -f
) ELSE (
    echo ds_agent service is missing. Proceeding with install.
    
    REM Run the install command
    "DSA_CUT.exe" -c -t -f
    exit /B 0
)
