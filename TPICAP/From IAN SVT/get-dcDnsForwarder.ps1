
$dcs =  Get-Content -Path "C:\Temp\DC.txt"

foreach($dc in $dcs){

Get-DnsServerForwarder -ComputerName $dc | Select-Object  -ExpandProperty ipaddress | select @{N='Server';E={[string]$dc}}, IPAddressToString

}