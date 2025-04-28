$servers = Get-Content -Path "C:\temp\servers2.txt" ##put the list in to the Text file
$username = "us\us da 1"          ##type the username
$password =  "N^Tq6$gPr6rIMtpRr" ### Type the password
$pass =  ConvertTo-SecureString -String $password -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass



$result = Foreach ($server in $servers){
Write-host $server
if (Get-WinEvent  -Computer $server -Credential $creds -FilterHashtable @{Logname='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'}){



Get-WinEvent  -Computer $server -Credential $creds -FilterHashtable  @{Logname='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'} |
    select @{N='Server';E={[string]$server}},@{N='User';E={$_.Properties[0].Value}}, TimeCreated} else {
    
    Write-Host "$server has no RDP log on" 
    
      }
    } 

    $result | export-csv c:\temp\USeolLog.csv ####Map the output location
    
    
    