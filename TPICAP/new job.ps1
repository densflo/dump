$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
    -Argument '-File D:\scripts\sync.ps1'
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 5)
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "SYNC WEBFOLDERS" -Action $Action -Trigger $Trigger -Settings $Settings -Description "Task to run unlock.ps1 every 5 mins" -Principal $Principal
