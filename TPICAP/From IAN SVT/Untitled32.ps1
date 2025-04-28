$Logdir = "C:\scripts\logs\"
$Logfile = "LocalAdmin-Audit-$(get-date -Format FileDateTimeUniversal).log"
$Logfile = Join-Path $Logdir $Logfile
$Tab = [char]9

$ADSecgroups = Get-Content -Path "C:\temp\audit.txt"
$validadmins = Get-Content -Path "D:\dashboard\toping.txt"
Function LogWrite
{
   Param ([string]$logstring)

   if (!(Test-Path $Logdir)) { New-Item -ItemType Directory -Force -Path $Logdir}

   $d = Get-Date -Format “dd/MM/yyyy HH:mm:ss”
   $logline = "$d $Tab $logstring"

   Add-content $Logfile -value $logline
}

foreach ($ADSec in $ADSecgroups){do

{
$Groups = Get-ADGroup -Identity "$ADSec" -Properties |  Get-ADGroupMember | Select-Object -ExpandProperty name

Write-Host "         $ADSec       " -BackgroundColor White -ForegroundColor DarkBlue
Write-Host "Admins for $ADSec"

foreach ($m1 in $Groups){    
     if($validadmins -contains $m1){
        Write-Host $m1 -ForegroundColor Green
     }else{
        if ($m1 -match "-Admin") { Write-Host $m1 -ForegroundColor Green } else {
        Write-Host $m1 -ForegroundColor Yellow
        LogWrite "$h $Tab WARNING $Tab Unexpected Admin Account found - $m1"
        }
     }
}


}while ($false)
}