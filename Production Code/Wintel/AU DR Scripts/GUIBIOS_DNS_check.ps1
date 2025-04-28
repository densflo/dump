$domainControllers = @('SNGPINFDCA02.global.icap.com', 'HK00WDSSAPP03P.global.icap.com','HK00WDSSAPP04P.global.icap.com','LDN1WS0356.global.icap.com','LDN2WS0279.global.icap.com','SYD2WS0020.global.icap.com','SYD1WS0020.global.icap.com')
$servers = @('AU00WGUIBKK01P', 'AU00WGUIHKG01P', 'AU00WGUIJAK01P', 'AU00WGUIMLA01P', 'AU00WGUISNG01P', 'AU00WGUISYD01P', 'AU00WGUITCM01P')

foreach ($dc in $domainControllers) {
    Write-Host "Domain Controller: $($dc.ToUpper())"
    Write-Host "---------------------------------"

    $summary = foreach ($server in $servers) {
        $result = Resolve-DnsName -Name "$server.global.icap.com" -Server $dc

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
