 function DC-Diag {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {



} 
process { 



$Domain = "corp.ad.tullib.com"



# Code
$DCs = Get-ADDomainController -filter * -server "$Domain"   
$AllDCs = $DCs  | foreach {$_.hostname} #| Where-Object {$_.hostname -like "LDNPINFDCG0*"} 
 
$AllDCDiags = @()

foreach ($DC in $AllDCs) 
{ 
Write-Host "Processing $DC" 
    $Dcdiag = (Dcdiag.exe /s:$DC) -split ('[\r\n]') 
    $Result = New-Object Object 
    $Result | Add-Member -Type NoteProperty -Name "ServerName" -Value $DC 
        $Dcdiag | ForEach-Object{ 
        Switch -RegEx ($_) 
        { 
         "Starting"      { $TestName   = ($_ -Replace ".*Starting test: ").Trim() } 
         "passed test|failed test" { If ($_ -Match "passed test") {  
         $TestStatus = "Passed"  
         }  
         Else  
         {  
         $TestStatus = "Failed"  
         } } 
        } 
        If ($TestName -ne $Null -And $TestStatus -ne $Null) 
        { 
         $Result | Add-Member -Name $("$TestName".Trim()) -Value $TestStatus -Type NoteProperty -force 
         $TestName = $Null; $TestStatus = $Null;
        } 
        
      }
      
$Date = get-date -f yyyy-MM-dd    
$AllDCDiags += $Result 
$AllDCDiags|Select-Object ServerName,Connectivity,Advertising,FrsEvent,DFSREvent,SysVolCheck,KccEvent,KnowsOfRoleHolders,MachineAccount,NCSecDesc,NetLogons,ObjectsReplicated,Replications,RidManager,Services,SystemLog,VerifyReferences,CheckSDRefDom,CrossRefValidation,LocatorCheck,Intersite | Export-Csv -NoTypeInformation -Path "D:\DCdiag\CORP\CorpDcDiag$date.csv"
} 

  }
}

DC-Diag 