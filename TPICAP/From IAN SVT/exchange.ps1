

Get-UDDashboard | Stop-UDDashboard
Get-PSSession -Name * | Remove-PSSession

Get-Module -All | Import-Module -Verbose



$5minuteschedule = New-UDEndpointSchedule -Every 5 -Minute

$DCdiagEndpoint = New-UDEndpoint -Schedule $5minuteschedule -Endpoint {
    $Cache:corpDcDiag = @()
    $Cache:corppath = @()
    $Cache:corppath = Get-ChildItem -Path 'D:\DCdiag\CORP' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:corpDcDiag = Import-Csv -LiteralPath $Cache:corppath

    $Cache:EURDcDiag = @()
    $Cache:EURpath = @()
    $Cache:EURpath = Get-ChildItem -Path 'D:\DCdiag\EUR' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:EURDcDiag = Import-Csv -LiteralPath $Cache:EURpath

    $Cache:APACDcDiag = @()
    $Cache:APACpath = @()
    $Cache:APACpath = Get-ChildItem -Path 'D:\DCdiag\APAC' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:APACDcDiag = Import-Csv -LiteralPath $Cache:APACpath

    $Cache:NADcDiag = @()
    $Cache:NApath = @()
    $Cache:NApath = Get-ChildItem -Path 'D:\DCdiag\NA' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:NADcDiag = Import-Csv -LiteralPath $Cache:NApath

    $Cache:ROOTADcDiag = @()
    $Cache:ROOTADpath = @()
    $Cache:ROOTADpath = Get-ChildItem -Path 'D:\DCdiag\ROOTAD' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ROOTADDcDiag = Import-Csv -LiteralPath $Cache:ROOTADpath

    $Cache:GLOBALDcDiag = @()
    $Cache:GLOBALpath = @()
    $Cache:GLOBALpath = Get-ChildItem -Path 'D:\DCdiag\GLOBAL' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:GLOBALADDcDiag = Import-Csv -LiteralPath $Cache:GLOBALpath

    $Cache:ICAPROOTDcDiag = @()
    $Cache:ICAPROOTpath = @()
    $Cache:ICAPROOTpath = Get-ChildItem -Path 'D:\DCdiag\ICAPROOT' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ICAPROOTDcDiag = Import-Csv -LiteralPath $Cache:ICAPROOTpath

    $Cache:ICAPDcDiag = @()
    $Cache:ICAPpath = @()
    $Cache:ICAPpath = Get-ChildItem -Path 'D:\DCdiag\ICAP' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ICAPDcDiag = Import-Csv -LiteralPath $Cache:ICAPpath

    $Cache:USDcDiag = @()
    $Cache:USpath = @()
    $Cache:USpath = Get-ChildItem -Path 'D:\DCdiag\US' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:USDcDiag = Import-Csv -LiteralPath $Cache:ICAPpath
}

$DCeventEndpoint = New-UDEndpoint -Schedule $5minuteschedule -Endpoint {

    $Cache:corpDcevent = @()
    $Cache:corppathevent = @()
    $Cache:corppathevent = Get-ChildItem -Path 'D:\' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:corpDCevent = Import-Csv -LiteralPath $Cache:corppathevent
}



$exusername = "srvcExchScripts@corp.ad.tullib.com"
$expass =  ConvertTo-SecureString -String "argwargv312;;" -AsPlainText -Force
$Cache:Credsex = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $exusername,$expass






$pages = @()

$pages += New-UDPage -name "Exchange" -Content {

New-UDLayout -Columns 1 -Content {




New-UDTabContainer -Tabs {
New-UDTab -Text 'Overview'                   -Content {
New-UDLayout -Columns 2 {

         New-UDColumn -Size 12 {  
                                                       
                                                       
New-UDTable -Title  "Last successful Mailbox Database Backup" -Headers @('Name','LastFullBackup') -Endpoint {

                                                              function check-exchange {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


Import-PSSession $Cache:Session1 -DisableNameChecking -AllowClobber


} 
process { 



<#################################################################
#          Last successful Mailbox Database Backup               # 
##################################################################>
Get-MailboxDatabase -Identity *DAG01-DB0* -Status | Select-Object Name, LastFullBackup | Sort-Object LastFullBackup 




  }
}

                  check-exchange | select Name,LastFullBackup | Out-UDTableData -Property @("Name","LastFullBackup") 
                         
                         
                                                               }
New-UDTable -Title  "Exchange (Windows) Service Health" -Headers @("MachineName","DisplayName","Status") -Endpoint {

                                                       function Check-ExchangeHealthService {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


Import-PSSession $Cache:Session1 -DisableNameChecking -AllowClobber

} 
process { 


<#################################################################
#              Exchange (Windows) Service Health                 # 
##################################################################>
$UnhealthyWindowsServices = @()

$ExchangeServers =  $(Get-MailboxServer | Where-Object AdminDisplayVersion -Like "Version 15.*" | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyWindowsServices += Get-Service -Name MSExchange* -ComputerName $objExchangeServer | Where-Object {($_.Name -ne "MSExchangeNotificationsBroker") -and ($_.Status -ne "Running")}
}

$UnhealthyWindowsServices 




  }
}
                         Start-Sleep -Seconds 5

                     Check-ExchangeHealthService | Sort-Object MachineName | select MachineName, DisplayName, @{N="Status";E={[string]$_.Status}} | Out-UDTableData -Property @("MachineName","DisplayName","status")
                         
                         

                                                               }
New-UDTable -Title  "Mailbox Database Copy Health" -Headers  @("Name","Status","InstanceStartTime","InternalStartupMessage","MailboxServer","ContentIndexState") -Endpoint {

                                                              function Copy-DatabasHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


Import-PSSession $Cache:Session2 -DisableNameChecking -AllowClobber

} 
process { 


<#################################################################
#                  Mailbox Database Copy Health                  # 
##################################################################>
$UnhealthyDatabases = @()

$ExchangeServers =  $(Get-MailboxServer | Where-Object AdminDisplayVersion -Like "Version 15.*" | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyDatabases += Get-MailboxDatabaseCopyStatus -Server $objExchangeServer | Where-Object {($_.Status -ne "Healthy") -and ($_.Status -ne "Mounted")}
}

$UnhealthyDatabases | Sort-Object Name




  }
}
                       
                       Copy-DatabasHealth | select Name,Status,InstanceStartTime,InternalStartupMessage,MailboxServer,ContentIndexState | Out-UDTableData -Property @("Name","Status","InstanceStartTime","InternalStartupMessage","MailboxServer","ContentIndexState")

                        
                                                               }
New-UDTable -Title  "HTTPS Service Health (OWA / ECP / Autodiscover etc)" -Headers  @("StatusCode","StatusDescription","URL") -Endpoint {
                                                                
                                                                function Http-ServiceHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {

 
Import-PSSession $Cache:Session2 -DisableNameChecking -AllowClobber 

} 
process { 

<#################################################################
#     HTTPS Service Health (OWA / ECP / Autodiscover etc)        # 
##################################################################>
$ExchangeServers =  $(Get-MailboxServer | Where-Object AdminDisplayVersion -Like "Version 15.*" | Sort-Object Name).Name

$HealthChecks = @(
    "/autodiscover/healthcheck.htm",
    "/mapi/healthcheck.htm",
    "/rpc/healthcheck.htm",
    "/oab/healthcheck.htm",
    "/owa/healthcheck.htm",
    "/ecp/healthcheck.htm",
    "/ews/healthcheck.htm",
    "/microsoft-server-activesync/healthcheck.htm"
)

$UnhealthyWebServices = @()

Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


ForEach ($objExchangeServer in $ExchangeServers){
        
        ForEach ($objHealthCheck in $Healthchecks){
            $UnhealthyWebServices += Invoke-WebRequest -Uri "https://$objExchangeServer.corp.ad.tullib.com$objHealthCheck" | Where-Object {$_.StatusCode -ne "200"}
        }
}

$UnhealthyWebServices




  }
}
    
                 Start-Sleep -Seconds 5
                  Http-ServiceHealth | select StatusCode,StatusDescription,@{N="URL";E={[string]$_.BaseResponse.ResponseUri.OriginalString}}  | Out-UDTableData -Property @("StatusCode","StatusDescription","URL")
                         
                                                               }
                                                           
                                                                    }
         
  
  
  }
New-UDLayout -Columns 1 {

New-UDTable -Title  "General Exchange Health" -Headers @("Server","CurrentHealthSetState","Name","TargetResource","HealthSetName","HealthGroupName","AlertValue","FirstAlertObservedTime","Description","DefinitionCreatedTime") -Endpoint {

                                                       function General-ExchangeHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {

Import-PSSession $Cache:Session3 -DisableNameChecking -AllowClobber


} 
process { 


<#################################################################
#                   General Exchange Health                      # 
##################################################################>
Get-MailboxServer | Where-Object AdminDisplayVersion -Like "Version 15.*" | Get-ServerHealth 




  }
}



General-ExchangeHealth | select Server,CurrentHealthSetState,Name,TargetResource,HealthSetName,HealthGroupName,AlertValue,FirstAlertObservedTime,Description,DefinitionCreatedTime | Out-UDTableData -Property @("Server","CurrentHealthSetState","Name","TargetResource","HealthSetName","HealthGroupName","AlertValue","FirstAlertObservedTime","Description","DefinitionCreatedTime")
                         


                                                               }

}
  }
New-UDTab -text 'Edge test' -Content {

                 
    New-UDCard -Title 'Test' -Links @(New-UDLink -url "file:///D:/bulk/EDGE_Exchange_Hourly_Report.html")

   }

 }

 }
}
$pages += New-UDPage -name "DCdiag" -Content {
New-UDTabContainer -Tabs{
New-UDTab  -Text Overview          -Content {

New-UDChart -Type Doughnut -Endpoint {


$Cache:corppathevent = Get-ChildItem -Path 'D:\' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }

$corpcount = $Cache:corppathevent | Where-Object {$_.LevelDisplayName -EQ 'Error'} | Measure-Object 

$corpresulterror = $corpcount | select count



$corpcount2 = $Cache:corppathevent | Where-Object {$_.LevelDisplayName -EQ 'Error'} | Measure-Object 

$corpresultwarning = $corpcount2 | select count

$corpresulterror,$corpresultwarning | Out-UDChartData -LabelProperty "error" -DataProperty $corpresulterror,$corpresultwarning

 

}


}
New-UDTab  -Text Corp              -Content {
  
  $corpDCtitle =  $Cache:corppath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $corpDCtitle -Headers @("ServerName","Connectivity","Advertising","FrsEvent","DFSREvent","SysVolCheck","KccEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","Replications","RidManager","Services","SystemLog","VerifyReferences","CheckSDRefDom","CrossRefValidation","LocatorCheck","Intersite") -Properties @("ServerName","Connectivity","Advertising","FrsEvent","DFSREvent","SysVolCheck","KccEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","Replications","RidManager","Services","SystemLog","VerifyReferences","CheckSDRefDom","CrossRefValidation","LocatorCheck","Intersite") -AutoRefresh -PageSize 100 -Endpoint {
       $Cache:corpDcDiag  | Out-UDGridData
  }

  }
New-UDTab  -Text EUR               -Content {
  
  $EurDCtitle = $Cache:EURpath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $EurDCtitle -Headers @("ServerName","Connectivity","Advertising","FrsEvent","DFSREvent","SysVolCheck","KccEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","Replications","RidManager","Services","SystemLog","VerifyReferences","CheckSDRefDom","CrossRefValidation","LocatorCheck","Intersite") -Properties @("ServerName","Connectivity","Advertising","FrsEvent","DFSREvent","SysVolCheck","KccEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","Replications","RidManager","Services","SystemLog","VerifyReferences","CheckSDRefDom","CrossRefValidation","LocatorCheck","Intersite") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:EURDcDiag | Out-UDGridData
  }

  }
New-UDTab  -Text NA                -Content {
  
  $NaDCtitle = $Cache:NApath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $NaDCtitle -Headers @("ServerName","Connectivity","Advertising","FrsEvent","DFSREvent","SysVolCheck","KccEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","Replications","RidManager","Services","SystemLog","VerifyReferences","CheckSDRefDom","CrossRefValidation","LocatorCheck","Intersite") -Properties @("ServerName","Connectivity","Advertising","FrsEvent","DFSREvent","SysVolCheck","KccEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","Replications","RidManager","Services","SystemLog","VerifyReferences","CheckSDRefDom","CrossRefValidation","LocatorCheck","Intersite") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:NADcDiag | Out-UDGridData
  }

  }
New-UDTab  -Text GLOBAL            -Content {
  
  $GlobalDCtitle = $Cache:GLOBALADpath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $GlobalDCtitle -Headers @("ServerName","Connectivity","Advertising","FrsEvent","DFSREvent","SysVolCheck","KccEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","Replications","RidManager","Services","SystemLog","VerifyReferences","CheckSDRefDom","CrossRefValidation","LocatorCheck","Intersite") -Properties @("ServerName","Connectivity","Advertising","FrsEvent","DFSREvent","SysVolCheck","KccEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","Replications","RidManager","Services","SystemLog","VerifyReferences","CheckSDRefDom","CrossRefValidation","LocatorCheck","Intersite") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:GLOBALADDcDiag | Out-UDGridData
  }

  }



 }
}



$ei = New-UDEndpointInitialization -Module @("C:\Program Files\WindowsPowerShell\Modules\VMware.VimAutomation.Core\10.1.0.8344055\VMware.VimAutomation.Core.psm1")
$Dashboard = New-UDDashboard  -Title 'Exchange Morning Check'  -FontColor white -NavBarFontColor white -Page $pages  -EndpointInitialization $ei 
Start-UDDashboard -Port 10001 -Dashboard $Dashboard -Endpoint @($DCdiagEndpoint,$DCeventEndpoint) -AdminMode