$ZoneName = "au.icap.com"
$Alias = "au00uetcora01p"
$Target = "au01uetcora01p"

$TTLMinutes = 5
$TTL = (New-TimeSpan -Minutes $TTLMinutes).TotalSeconds

$ExistingRecord = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $Alias -Type 5 -ErrorAction SilentlyContinue

if ($ExistingRecord) {
    Write-Host "Deleting existing CNAME record..."
    Remove-DnsServerResourceRecord -ZoneName $ZoneName -InputObject $ExistingRecord -Force
}

Write-Host "Creating new CNAME record..."
Add-DnsServerResourceRecordCName -Name $Alias.ToLower() -HostNameAlias "$Target.$ZoneName" -ZoneName $ZoneName.ToLower() -TimeToLive $TTL

$NewRecord = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $Alias.ToLower() -Type 5

$TTLMinutes = [math]::Round($NewRecord.TimeToLive / 60)

Write-Host "New CNAME record created:"
Write-Host "Alias: $($NewRecord.HostName)"
Write-Host "Target: $($NewRecord.HostNameAlias)"
Write-Host "TTL: $TTLMinutes minutes"
