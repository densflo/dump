
$servers = Get-Content -Path c:\test.txt

function get-localadmin {  
param ($strcomputer)  
  
$admins = Get-WmiObject win32_groupuser –computer $strcomputer   
$admins = $admins |? {$_.groupcomponent –like '*"Administrators"'}  
  
$admins |% {  
$_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul  
$matches[1].trim('"') + “\” + $matches[2].trim('"')  
}  
}

foreach($server in $servers){do{

Write-Host "Server Name $server"

get-localadmin -strcomputer $server | ft




}while ($false)
}