
$servers = Get-Content -Path "C:\temp\qualys2.txt"
$CorpDCusername = "corp\corp da 2"
$CorpDCpass =  ConvertTo-SecureString -String "6cHyZZB#Wpmj^l2gM2G" -AsPlainText -Force
$CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass




$result = foreach ($servername in $servers){

$status = 
Try{
if(Get-WMIObject -Query "select * from win32_service where name='QualysAgent'" -ComputerName $servername -Credential $CorpCreds -ErrorAction SilentlyContinue | Where-Object State  -EQ 'running'){
Write-Host "$servername ok" -BackgroundColor Green
Write-Output 'running'}
elseif(Get-WMIObject -Query "select * from win32_service where name='QualysAgent'" -ComputerName $servername -Credential $CorpCreds -ErrorAction SilentlyContinue | Where-Object State  -EQ 'stopped'){
Write-Host "$servername stopped" -BackgroundColor Yellow
Write-Output 'stopped'

}else{
try{
write-host "$servername service not installed" -BackgroundColor Red
Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0}
Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {New-Item "c:\temp" -ItemType directory -ErrorAction SilentlyContinue}
Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {New-Item "c:\temp\QualysPackage" -ItemType directory -ErrorAction SilentlyContinue}
Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {New-Item "c:\Program Files (x86)\ICAP\QualysPackage" -ItemType directory -ErrorAction SilentlyContinue}

   $sess = New-PSSession -ComputerName $servername -Credential $CorpCreds

   Copy-Item  "\\10.90.80.243\bulk\qualys\certs" -Destination 'C:\Program Files (x86)\icap\qualyspackage' -Recurse -ToSession $sess
   Copy-Item  "\\10.90.80.243\bulk\qualys\QualysCloudAgent.exe" -Destination 'C:\Program Files (x86)\icap\qualyspackage' -Recurse -ToSession $sess
   Copy-Item  "\\10.90.80.243\bulk\qualys\QualysCloudAgentProdnew.ps1" -Destination 'C:\temp\qualyspackage' -Recurse -ToSession $sess
   Copy-Item  "\\10.90.80.243\bulk\qualys\subnetgwdist.csv" -Destination 'C:\Program Files (x86)\icap\qualyspackage' -Recurse -ToSession $sess
                                      

Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {powershell.exe  'C:\temp\QualysPackage\QualysCloudAgentProdnew.ps1' } 

write-host "tried to install qualys on $servername " -BackgroundColor yellow
Remove-PSSession -Session $sess
Start-Sleep -Seconds 5
}finally{

      if(Get-WMIObject -Query "select * from win32_service where name='QualysAgent'" -ComputerName $servername -Credential $CorpCreds -ErrorAction SilentlyContinue | Where-Object State  -EQ 'running'){
      
      Write-Host "Qualys service is now running on $servername"
      
      }else{Write-Host "instalation of qualys on $servername failed" }


      }

Write-Output 'not installed'}
}catch{Write-Host "$servername access issue" -ForegroundColor RED
Write-Output "error"
       }finally{$Error.Clear()}
[PSCustomObject] @{
'Server Name' = $servername
'Qualys Status' = $status

  }

 }

$result | Export-Csv -Path C:\temp\qualysscan1.csv -NoTypeInformation