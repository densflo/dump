
$CorpDCusername = "inavarrete-a@corp.ad.tullib.com"
$CorpDCpass =  ConvertTo-SecureString -String "I@n@rif121087" -AsPlainText -Force
$CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass
$date = Get-Date -Format o | ForEach-Object {$_ -replace “:”, “.”}

Connect-MsolService -Credential $CorpCreds -AzureEnvironment AzureCloud

$license = Get-MsolAccountSku | sort ConsumedUnits -Descending | Select-Object  @{N="AccountSkuId";E={[string]$_.AccountSkuId}}, @{N="ActiveUnits";E={[string]$_.ActiveUnits}} , @{N="ConsumedUnits";E={[string]$_.ConsumedUnits}}, @{N="Remaining";E={[string]$_.ActiveUnits - [string]$_.ConsumedUnits}}

$license | Export-Csv -Path "\\LDN1WS9724\bulk\Office365\O365License-$date.csv" -NoTypeInformation

