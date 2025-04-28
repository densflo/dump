
$servers = Get-Content -Path "C:\temp\audit.txt"


$CorpDCusername = "corp\inavarrete-a"
$CorpDCpass =  ConvertTo-SecureString -String "I@n@rif121087" -AsPlainText -Force
$CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass



 $output = foreach ($server in $servers){

if (Test-Connection $server -Count 2){



Get-WmiObject -Class SoftwareLicensingProduct -Filter 'ProductKeyId != NULL' -ComputerName $server -Credential $CorpCreds | Select-Object -Property @{Name='Server Name';Expression={$server}}, Name, Description, LicenseStatus, EvaluationEndDate, PartialProductKey, RemainingAppRearmCount 
 


 }
  
  else{
  
     New-Object -TypeName PSCustomObject -Property @{
                                                               'Server Name'  = $server
                                                                Name = 'N/A'
                                                                Description = 'unreachable'
                                                                LicenseStatus = 'N/A'
                                                                EvaluationEndDate = 'N/A'
                                                                PartialProductKey = 'N/A'
                                                                RemainingAppRearmCount = 'N/A'

       
    }
}

}

$output | export-csv -Path C:\temp\Win2008Scan.csv -NoTypeInformation