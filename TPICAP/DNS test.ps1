# Import the Active Directory module to ensure access to AD-specific cmdlets
Import-Module ActiveDirectory

# Define the DNS record to be resolved
$dnsRecord = "smtprelay.corp.ad.tullib.com"

# Query each DC 10 times and gather results
$attempts = 10
$queryResults = @{}

# Get all domain controllers in the current user's domain
$dcs = Get-ADDomainController -Filter *

foreach ($dc in $dcs) {
    $withIPv4Count = 0
    $withoutIPv4Count = 0
    
    for ($i = 0; $i -lt $attempts; $i++) {
        # Perform the DNS query from the target DC
        try {
            $results = Resolve-DnsName -Name $dnsRecord -Server $dc.HostName -ErrorAction Stop
            # Check if at least one IP v4 address is returned in the result
            $hasIPv4 = $results | Where-Object { $_.QueryType -eq 'A' }
            if ($hasIPv4) {
                $withIPv4Count++
            } else {
                $withoutIPv4Count++
            }
            Write-Host "Query ${i}: DNS query succeeded - DC: $($dc.HostName)"
        } catch {
            $withoutIPv4Count++
            Write-Host "Query ${i}: DNS query failed or no IPv4 address - DC: $($dc.HostName)"
        }
    }

    # Store the results in a hash table
    $queryResults[$dc.Name] = @{
        WithIPv4 = $withIPv4Count
        WithoutIPv4 = $withoutIPv4Count
    }
}

# Compile the results into an array of custom objects
$results = foreach ($resultKey in $queryResults.Keys) {
    [PSCustomObject]@{
        DomainController = $resultKey
        WithIPv4         = $queryResults[$resultKey].WithIPv4
        WithoutIPv4      = $queryResults[$resultKey].WithoutIPv4
    }
}

# Output the report
Write-Host "`nReport on DNS Resolution Attempts:`n"
$results | Format-Table -Property DomainController, WithIPv4, WithoutIPv4 -AutoSize
