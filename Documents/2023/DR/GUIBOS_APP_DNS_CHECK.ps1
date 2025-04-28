$domainControllers = @('SYD1WS0021.au.icap.com','SYD2WS0021.au.icap.com')
$servers = @('sydguibos1p','ultguibos1p')

foreach ($dc in $domainControllers) {
    Write-Host "Domain Controller: $($dc.ToUpper())"
    Write-Host "---------------------------------"

    $summary = foreach ($server in $servers) {
        $result = Resolve-DnsName -Name "$server.au.icap.com" -Server $dc

        foreach ($record in $result) {
              $alias = $record.NameHost
                $ipAddress = $record.IPAddress
            

            [PsCustomObject]@{
                DomainController = $dc
                Record = $server
                RecordType = $record.Type
                Alias = $alias
                IPAddress = $ipAddress
                TTL = $record.TTL
            }
        }
    }

    $summary | Format-Table -AutoSize
    Write-Host ""
}
