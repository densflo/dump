$ZoneName = "au.icap.com"
$Hostname = "au00uetcora01p"
$IPAddress = "10.242.33.249"

$TTLMinutes = 5
$TTL = (New-TimeSpan -Minutes $TTLMinutes).TotalSeconds

$ExistingRecord = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $Hostname -Type A -ErrorAction SilentlyContinue

if ($ExistingRecord) {
    Write-Host "Deleting existing A record..."
    Remove-DnsServerResourceRecord -ZoneName $ZoneName -InputObject $ExistingRecord -Force
}

Write-Host "Creating new A record..."
Add-DnsServerResourceRecordA -Name $Hostname -IPv4Address $IPAddress -ZoneName $ZoneName -TimeToLive $TTL

$NewRecord = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $Hostname -Type A

Write-Host "New A record created:"
Write-Host "Hostname: $($NewRecord.HostName)"
Write-Host "IP Address: $($NewRecord.RecordData.IPv4Address)"
Write-Host "TTL: $TTLMinutes minutes"
