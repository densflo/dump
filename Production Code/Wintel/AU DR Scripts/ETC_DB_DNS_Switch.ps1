param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("PROD", "DR")]
    [string]$Switch
)

# Prompt user to enter their credentials for DNS modification
$UserCredential = Get-Credential -Message "Enter your username and password for DNS modification"

# List of domain controllers where DNS modifications will be applied
$domainControllers = @(
    'SYDPINFDCG01.corp.ad.tullib.com',
    'SYDPINFDCG02.corp.ad.tullib.com',
    'SYDPINFDCG04.corp.ad.tullib.com',
    'LDN1WS0060.corp.ad.tullib.com'
)

# List of DNS zones to be modified
$ZoneNames = @("corp.ad.tullib.com", "au.icap.com")

# Set the TTL (Time To Live) for DNS records to 1 minute
$TTLMinutes = 5
$TTL = New-TimeSpan -Minutes $TTLMinutes


# List of hostnames for DNS records
$Hostnames = @("au00uetcora01p", "test-au01uetcora01p")

# Hash table containing IP mappings for 'PROD' and 'DR' modes
$ipMapping = @{
    "PROD" = @{
        "au00uetcora01p" = "10.242.33.249";
        "au01uetcora01p" = "10.241.33.101";
    };
    "DR" = @{
        "au00uetcora01p" = "10.241.33.101";
        "au01uetcora01p" = "10.241.33.101";
    }
}

# Iterate through each domain controller
foreach ($dc in $domainControllers) {
    # Use Invoke-Command to execute DNS changes on the remote domain controller
    Invoke-Command -ComputerName $dc -Credential $UserCredential -ScriptBlock {
        param ($ZoneNames, $Hostnames, $TTL, $Switch, $ipMapping)
        Import-Module DnsServer
        # Iterate through each DNS zone
        foreach ($zone in $ZoneNames) {
            # Iterate through each hostname
            foreach ($hostname in $Hostnames) {
                # Retrieve the IP address mapping based on the mode (PROD/DR)
                $IPAddress = $ipMapping[$Switch][$hostname]

                # Check for an existing DNS A record and store it in $ExistingRecord
                $ExistingRecord = Get-DnsServerResourceRecord -ZoneName $zone -Name $hostname -RRType "A" -ErrorAction SilentlyContinue

                # If an existing record is found, delete it
                if ($ExistingRecord) {
                    Write-Host "Deleting existing A record for $hostname on $($using:dc)..."
                    Remove-DnsServerResourceRecord -ZoneName $zone -InputObject $ExistingRecord -Force
                }

                # Create a new A record with the specified IP address
                Write-Host "Creating new A record for $hostname on $($using:dc)..."
                Add-DnsServerResourceRecordA -Name $hostname.ToLower() -IPv4Address $IPAddress -ZoneName $zone.ToLower() -TimeToLive $TTL

                # Retrieve the newly created A record to confirm its creation
                $NewRecord = Get-DnsServerResourceRecord -ZoneName $zone -Name $hostname.ToLower() -RRType "A"

                # Calculate the TTL for the new record in minutes
                $TTLMinutes = [math]::Round($NewRecord.TimeToLive.TotalSeconds / 60)

                # Output the details of the new DNS record to the console
                Write-Host "New A record created for $hostname on $($using:dc):"
                Write-Host "Hostname: $($NewRecord.HostName)"
                Write-Host "IP Address: $($NewRecord.RecordData.IPv4Address)"
                Write-Host "TTL: $TTLMinutes minutes"
            }
        }
    } -ArgumentList $ZoneNames, $Hostnames, $TTL, $Switch, $ipMapping
}
