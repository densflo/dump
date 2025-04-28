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

function Check-Members{

$h = $SecGroup
$m = $members

Write-Host "Admins for $h"
foreach ($m1 in $m)
{    
     if($validadmins -contains $m){
        Write-Host $m -ForegroundColor Green
     }else{
        if ($m -match "-Admin") { Write-Host $m -ForegroundColor Green } else {
        Write-Host $m -ForegroundColor Yellow
        LogWrite "$h $Tab WARNING $Tab Unexpected Admin Account found - $m"
        }
     }
}
}

$SecGroup = Get-Content -Path "C:\temp\audit.txt"

foreach ($members in $SecGroup)
{
    

    LogWrite "$SecGroup $Tab Checking $server"



    {
        Write-Host "         $SecGroup       " -BackgroundColor White -ForegroundColor DarkBlue

        $admin = Get-ADSecuritymembers $members
        Check-Members $admin
    }
   
}