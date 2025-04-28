$Logdir = "C:\scripts\DomainSecurityGroupAuditLog\"
$Logfile = "DomainSecurityGroup-Audit-$(get-date -Format FileDateTimeUniversal).log"
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
$Groups = Get-ADGroup -Identity "$ADSec" |  Get-ADGroupMember | Select-Object -ExpandProperty name

Write-Host "         $ADSec       " -BackgroundColor White -ForegroundColor DarkBlue
Write-Host "Admins for $ADSec"

LogWrite "$ADSec $Tab Checking $ADSec"

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

### send email ##

$auditcheck = Get-ChildItem -Path "C:\scripts\DomainSecurityGroupAuditLog" -Recurse   | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1

if (Get-Content "C:\scripts\DomainSecurityGroupAuditLog\$auditcheck" | Select-String -SimpleMatch "WARNING"){

 

 $body = "Hi <br>
 <br>
 Script has Detected  unauthorize AD Security Group modification for Corp Domain.<br>
 <br>
 Please See attached file<br>
 <br>
 Thank you!
 "
 $attachedfile = "C:\scripts\DomainSecurityGroupAuditLog\$auditcheck"
 $date      = Get-Date
 $SMTPServer = "emeasmtp.eur.ad.tullib.com"
 $ToAddress = "ian.navarrete-cti@tpicap.com"
 $FromAddress = "WintelAudit@tpicap.com"
 $Subject = "Corp Domain Security Group audit $date" 

 Send-Mailmessage -From $FromAddress -To $ToAddress -Subject $Subject -Attachments $attachedfile  -BodyAsHtml -body $body  -Priority Normal -SmtpServer $SMTPServer
 }