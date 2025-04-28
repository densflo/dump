$CorpDCusername = "corp\inavarrete-a"
$CorpDCpass =  ConvertTo-SecureString -String "I@n@rif121087" -AsPlainText -Force
$Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass

$servers = Get-Content -Path "C:\temp\servers.txt"

foreach ($server in $servers){


Invoke-Command -ComputerName $server -Credential $Creds -ScriptBlock {

$Localpass =  ConvertTo-SecureString -String 'Kz7aG0VzNRJ6RNrJUq%$)6cX&QAHV@X3' -AsPlainText -Force

New-LocalUser  -Name "EMEALESA" -Password $Localpass  -FullName "Third User" -Description "Local Built in" | Add-LocalGroupMember -Group administrators

 } 

}