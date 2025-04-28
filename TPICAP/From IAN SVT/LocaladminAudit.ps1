### Configuration ###

$Logdir = "C:\scripts\logs\"
$Logfile = "LocalAdmin-Audit-$(get-date -Format FileDateTimeUniversal).log"
$Logfile = Join-Path $Logdir $Logfile
$Tab = [char]9

# Whitelist Users and Groups"
$validadmins = "EMEALESA"

### Functions ###
Function LogWrite
{
   Param ([string]$logstring)

   if (!(Test-Path $Logdir)) { New-Item -ItemType Directory -Force -Path $Logdir}

   $d = Get-Date -Format “dd/MM/yyyy HH:mm:ss”
   $logline = "$d $Tab $logstring"

   Add-content $Logfile -value $logline
}

Function Get-NetLocalGroup {
[cmdletbinding()]

Param(
[Parameter(Position=0)]
[ValidateNotNullorEmpty()]
[object[]]$Computername=$env:computername,
[ValidateNotNullorEmpty()]
[string]$Group = "Administrators",
[switch]$Asjob
)

Write-Verbose "Getting members of local group $Group"

#define the scriptblock
$sb = {
 Param([string]$Name = "Administrators")
$members = net localgroup $Name | 
 where {$_ -AND $_ -notmatch "command completed successfully"} | 
 select -skip 4
New-Object PSObject -Property @{
 Computername = $env:COMPUTERNAME
 Group = $Name
 Members=$members
 }
} #end scriptblock

#define a parameter hash table for splatting
$paramhash = @{
 Scriptblock = $sb
 HideComputername=$True
 ArgumentList=$Group
 }

if ($Computername[0] -is [management.automation.runspaces.pssession]) {
    $paramhash.Add("Session",$Computername)
}
else {
    $paramhash.Add("Computername",$Computername)
}

if ($asjob) {
    Write-Verbose "Running as job"
    $paramhash.Add("AsJob",$True)
}

#run the command
Invoke-Command @paramhash | Select * -ExcludeProperty RunspaceID

} #end Get-NetLocalGroup

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

$servers = Get-Content -Path "C:\temp\servers.txt"

foreach ($s in $servers)
{
    

    $ping = Test-Connection $s -Count 1 -Quiet

    LogWrite "$server $Tab Checking $server"

    if ($ping){
        Write-Host "         $s       " -BackgroundColor White -ForegroundColor DarkBlue

        $admins = Get-NetLocalGroup $s
        Check-Members $admins
    }else{
        Write-Warning "Could not connect to $s"
        LogWrite "$s $Tab Could not connect to $s"
    }
    Write-Host "                                    " -BackgroundColor White -ForegroundColor DarkBlue
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