$OldObj = Get-DnsServerResourceRecord -Name "LDN1WS9724" -ZoneName "corp.ad.tullib.com" -RRType "A"
$NewObj = $OldObj.Clone()
$NewObj.TimeToLive = [System.TimeSpan]::FromHours(0.18)
$updateip = '10.90.80.243'
$NewObj.RecordData.ipv4address = [System.Net.IPAddress]::parse($updateip)
Set-DnsServerResourceRecord -NewInputObject $NewObj -OldInputObject $OldObj -ZoneName "corp.ad.tullib.com" -PassThru