

##### Changing to AU00WGUIBKK01P
$prod = 'AU00WGUIAPP01P'
$dr = 'AU00WGUIBKK01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUIHKG01P
$prod = 'AU00WGUIAPP02P'
$dr = 'AU00WGUIHKG01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUIJAK01P
$prod = 'AU00WGUIAPP03P'
$dr = 'AU00WGUIJAK01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUIMLA01P
$prod = 'AU00WGUIAPP04P'
$dr = 'AU00WGUIMLA01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUIRST01P
$prod = 'AU00WGUIAPP05P'
$dr = 'AU00WGUIRST01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUISNG01P
$prod = 'AU00WGUIAPP06P'
$dr = 'AU00WGUISNG01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUISYD01P
$prod = 'AU00WGUIAPP07P'
$dr = 'AU00WGUISYD01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUITCM01P
$prod = 'AU00WGUIAPP08P'
$dr = 'AU00WGUITCM01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"


