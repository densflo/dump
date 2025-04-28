New-UDTable -Title  "HTTPS Service Health" -Headers  @("Name","Status","InstanceStartTime","InternalStartupMessage","MailboxServer","ContentIndexState") -Endpoint {

                                                       

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
            $UnhealthyWebServices += Invoke-WebRequest -Uri "https://$objExchangeServer.corp.ad.tullib.com$objHealthCheck" 
        }
}

$UnhealthyWebServices




  }
}

Http-ServiceHealth | select StatusCode,StatusDescription,@{N="URL";E={[string]$_.BaseResponse.ResponseUri.OriginalString}}  | Out-UDTableData -Property @("StatusCode","StatusDescription","URL")
                         
                                                               }