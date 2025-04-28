# Define the list of domain names
$domains = @(
    "hkinforeach.liquidnet.biz",
    "hkinforeach02.liquidnet.biz",
    "hk1pbtrd01.liquidnet.biz",
    "hk1pbtrd02.liquidnet.biz",
    "hk1pbtrdbk01.liquidnet.biz",
    "hkinforeach.ae.tpicap.com",
    "hkinforeach02.ae.tpicap.com"
)

# Prepare a hashtable to accumulate results by domain
$resultsTable = @{}

foreach ($domain in $domains) {
    try {
        # Perform a DNS lookup for each domain
        $dnsRecords = Resolve-DnsName $domain -ErrorAction Stop
        
        # Initialize the domain entry in the hashtable if not already present
        if (-not $resultsTable.ContainsKey($domain)) {
            $resultsTable[$domain] = @()
        }
        
        # Collect all relevant DNS records with TTL
        foreach ($record in $dnsRecords) {
            $resultsTable[$domain] += New-Object PSObject -Property @{
                Domain = $domain
                RecordType = $record.QueryType
                RecordName = $record.Name
                RecordData = if ($record.QueryType -eq 'SOA') {$record.PrimaryServer} elseif ($record.QueryType -eq 'A') {$record.IPAddress} elseif ($record.QueryType -eq 'CNAME') {$record.Name} else {$null}
                TTL = $record.TTL
            }
        }
    } catch {
        Write-Host "Failed to resolve DNS for $domain"
    }
}

# Display the results grouped by domain and formatted as a table
foreach ($key in $resultsTable.Keys) {
    Write-Host "Results for domain: $key`n"
    $resultsTable[$key] | Format-Table -AutoSize
    Write-Host ""  # Empty line for better readability between domain results
}