



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
$vusername = "srvcExchScripts@corp.ad.tullib.com"
$vpass =  ConvertTo-SecureString -String "argwargv312;;" -AsPlainText -Force
$Cache:Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $vusername,$vpass


$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Creds
Import-PSSession $Session -DisableNameChecking -AllowClobber


} 
process { 


<#################################################################
#     	               POP3 Service Health                       # 
##################################################################>
$UnhealthyPOP = @()

$ExchangeServers =  $(Get-MailboxServer | Where-Object AdminDisplayVersion -Like "Version 15.*" | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyPOP += Test-NetConnection $objExchangeServer -Port 110 
}

$UnhealthyPOP 



  }
}

Http-ServiceHealth |Sort-Object ComputerName |FT
Disconnect-PSSession -Session $Session