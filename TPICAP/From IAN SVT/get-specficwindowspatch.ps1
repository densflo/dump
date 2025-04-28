$servers = Get-Content -Path "\\10.90.80.243\bulk\windowsKBfix\servers.txt"


foreach ($server in $servers){

Get-HotFix -ComputerName $server -Id KB900873

}

