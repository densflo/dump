$servers = Get-Content -Path C:\temp\appd.txt


foreach($server  in $servers ){

Copy-Item -Path "\\10.90.80.243\bulk\appd\Windows10.0-KB900873-x64.exe" -Destination "\\$server\C$\temp" 

}