$zones = Get-Content -Path C:\zones.txt

foreach ($zone in $zones){

Get-DnsServerResourceRecord -ZoneName $zone -Name "dn1ws035n01" -ErrorAction SilentlyContinue

}