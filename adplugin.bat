@echo off

:: Check if DC role is installed
where /Q dcdiag > nul
if ERRORLEVEL 1 goto NOT_DOMAIN_CONTROLLER

:: AD Connectivity Test
echo ^<^<^<ad_connectivity^>^>^>
dcdiag /test:connectivity /s:%computername%

:: AD Advertising Test
echo ^<^<^<ad_advertising^>^>^>
dcdiag /test:advertising /s:%computername%

goto :EOF

:NOT_DOMAIN_CONTROLLER
echo Server is not a domain controller
