

##### Changing to AU00WGUIBKK01P
$prod = 'AU00WGUIBKK01P'
$dr = 'AU00WGUIAPP01P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUIHKG01P
$prod = 'AU00WGUIHKG01P'
$dr = 'AU00WGUIAPP02P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUIJAK01P
$prod = 'AU00WGUIJAK01P'
$dr = 'AU00WGUIAPP03P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUIMLA01P
$prod = 'AU00WGUIMLA01P'
$dr = 'AU00WGUIAPP04P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUIRST01P
$prod = 'AU00WGUIRST01P'
$dr = 'AU00WGUIAPP05P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUISNG01P
$prod = 'AU00WGUISNG01P'
$dr = 'AU00WGUIAPP06P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUISYD01P
$prod = 'AU00WGUISYD01P'
$dr = 'AU00WGUIAPP07P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"

##### Changing to AU00WGUITCM01P
$prod = 'AU00WGUITCM01P'
$dr = 'AU00WGUIAPP08P'

$OldObj = Get-DnsServerResourceRecord -Name "$prod" -ZoneName "global.icap.com" -RRType "A"
$NewObj = $OldObj.Clone()
Add-DnsServerResourceRecordA -Name "$dr" -ZoneName "global.icap.com" -AllowUpdateAny -IPv4Address $NewObj.RecordData.ipv4address -TimeToLive 00:05:00
Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "A" -Name "$prod" -Force
Get-DnsServerResourceRecord -Name "$dr" -ZoneName "global.icap.com" -RRType "A"


