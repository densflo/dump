### Configuration ###

$Logdir = "C:\scripts\logs\"
$Logfile = "LocalAdmin-Audit-$(get-date -Format FileDateTimeUniversal).log"
$Logfile = Join-Path $Logdir $Logfile
$Tab = [char]9

# Whitelist Users and Groups"
$validadmins = Get-Content -Path "D:\dashboard\toping.txt"

### Functions ###
Function LogWrite
{
   Param ([string]$logstring)

   if (!(Test-Path $Logdir)) { New-Item -ItemType Directory -Force -Path $Logdir}

   $d = Get-Date -Format “dd/MM/yyyy HH:mm:ss”
   $logline = "$d $Tab $logstring"

   Add-content $Logfile -value $logline
}

function Get-ADSecuritymembers {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ADgroup       
)  

begin {






}  
process { 


Get-ADGroup -Identity "$ADgroup" |  Get-ADGroupMember | select name


  }
end {
  
 }
}

function Check-Members($admingroup){

$h = $admingroup.Computername
$m = $admingroup.Members

Write-Host "Admins for $h"
foreach ($m1 in $m)
{    
     if($validadmins -contains $m1){
        Write-Host $m1 -ForegroundColor Green
     }else{
        if ($m1 -match "-Admin") { Write-Host $m1 -ForegroundColor Green } else {
        Write-Host $m1 -ForegroundColor Yellow
        LogWrite "$h $Tab WARNING $Tab Unexpected Admin Account found - $m1"
        }
     }
}
}

$SecGroup = Get-Content -Path "C:\temp\audit.txt"

foreach ($members in $SecGroup)
{
    

    LogWrite "$SecGroup $Tab Checking $server"



    {
        Write-Host "         $members       " -BackgroundColor White -ForegroundColor DarkBlue

        $admins = Get-ADSecuritymembers $members
        Check-Members $admins
    }
   
}

### send email ##

$auditcheck = Get-ChildItem -Path "C:\scripts\logs" -Recurse   | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1

 if (Get-Content "C:\scripts\logs\$auditcheck" | Select-String -SimpleMatch "WARNING"){

 

 $body = "Hi <br>
 <br>
 Script has Detected  unauthorize Local admin moddifications for Corp servers.<br>
 <br>
 Please See attached file<br>
 <br>
 Thank you!
 "
 $attachedfile = "C:\scripts\logs\$auditcheck"
 $date      = Get-Date
 $SMTPServer = "emeasmtp.eur.ad.tullib.com"
 $ToAddress = "ian.navarrete-cti@tpicap.com"
 $FromAddress = "WintelAudit@tpicap.com"
 $Subject = "corp Local admin audit $date" 

 Send-Mailmessage -From $FromAddress -To $ToAddress -Subject $Subject -Attachments $attachedfile  -BodyAsHtml -body $body  -Priority Normal -SmtpServer $SMTPServer
 
 
 
 
 }else{}


### End Script ###