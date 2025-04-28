$domainControllers = @('SYDPINFDCG01.corp.ad.tullib.com', 'SYDPINFDCG02.corp.ad.tullib.com', 'SYDPINFDCG04.corp.ad.tullib.com', 'LDN1WS0060.corp.ad.tullib.com')
$zones = @("corp.ad.tullib.com", "au.icap.com")
$hostnames = @("au00uetcora01p", "au01uetcora01p")

$results = @()

foreach ($zoneName in $zones) {
    foreach ($dc in $domainControllers) {
        foreach ($hostname in $hostnames) {
            $fullyQualifiedHostname = "$hostname.$zoneName"
            Write-Host "Checking records for $fullyQualifiedHostname on $dc..."

            try {
                $dnsRecords = Resolve-DnsName -Name $fullyQualifiedHostname -Server $dc -Type "ANY" -ErrorAction Stop
                foreach ($record in $dnsRecords) {
                    switch ($record.QueryType) {
                        "A" {
                            $results += [PSCustomObject]@{
                                DomainController = $dc
                                Zone             = $zoneName
                                Hostname         = $hostname
                                RecordType       = "A"
                                IPAddress        = $record.IPAddress
                                TTL              = ($record.TTL/60)
                            }
                            Write-Host "`tFound A record with IP: $($record.IPAddress) and TTL: $($record.TTL)"
                        }
                        "CNAME" {
                            $results += [PSCustomObject]@{
                                DomainController = $dc
                                Zone             = $zoneName
                                Hostname         = $hostname
                                RecordType       = "CNAME"
                                Target           = $record.NameHost
                                TTL              = ($record.TTL/60)
                            }
                            Write-Host "`tFound CNAME record pointing to: $($record.NameHost) with TTL: $($record.TTL)"
                        }
                    }
                }
            } catch {
                Write-Host "`tNo records found for $fullyQualifiedHostname."
            }
        }
    }
}

# Display the results in separate tables for each hostname
foreach ($hostname in $hostnames) {
    Write-Host "Summary of DNS records found for [$hostname]:"
    $hostnameResults = $results | Where-Object { $_.Hostname -eq $hostname }
    $hostnameResults | Format-Table -AutoSize
}
