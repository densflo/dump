$secgroup = Get-Content -Path C:\temp\audit.txt




foreach ($sec in $secgroup){



Get-ADGroup -Identity "$sec" |  Get-ADGroupMember | select @{N="ServerName";E={[string]$Sec}},name


}