$OldObj = Get-DnsServerResourceRecord -Name "host23" -ZoneName "corp.ad.tullib.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "LDN1WS9724" -ZoneName "corp.ad.tullib.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00

Remove-DnsServerResourceRecord -ZoneName "corp.ad.tullib.com" -RRType "A" -Name "host23" -Force

Get-DnsServerResourceRecord -Name "LDN1WS9724" -ZoneName "corp.ad.tullib.com" -RRType "A"