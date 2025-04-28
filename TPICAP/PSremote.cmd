@echo off
rem Enable Windows Remote Management (WinRM)
winrm quickconfig -q
winrm set winrm/config/service @{AllowUnencrypted="true"}
winrm set winrm/config/service/auth @{Basic="true"}

rem Enable PowerShell Remoting
powershell.exe Set-ExecutionPolicy RemoteSigned
powershell.exe Enable-PSRemoting -Force
