$domainControllers = @('SYDPINFDCG01.corp.ad.tullib.com','SYDPINFDCG02.corp.ad.tullib.com','SYDPINFDCG04.corp.ad.tullib.com','LDN1WS0060.corp.ad.tullib.com')
$servers = @('tmsprod-apac')

foreach ($dc in $domainControllers) {
    Write-Host "Domain Controller: $($dc.ToUpper())"
    Write-Host "---------------------------------"

    $summary = foreach ($server in $servers) {
        $result = Resolve-DnsName -Name "$server.corp.ad.tullib.com" -Server $dc

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
