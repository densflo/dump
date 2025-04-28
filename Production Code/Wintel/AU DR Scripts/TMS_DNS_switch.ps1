function Switch-TMSDNS {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('DR', 'Prod')]
        [string]$Environment
    )

    $domainControllers = @('SYDPINFDCG01.corp.ad.tullib.com','SYDPINFDCG02.corp.ad.tullib.com','SYDPINFDCG04.corp.ad.tullib.com','LDN1WS0060.corp.ad.tullib.com')
    $cred = Get-Credential
    $dnsrecord = 'tmsprod-apac'

    $scriptBlock = {
        param ($Environment, $dnsrecord, $cred)
        
        Write-Host "Domain Controller: $($env:computername.ToUpper())"
        Write-Host "---------------------------------"
        $ttl = New-TimeSpan -Minutes 1

        if ($Environment -eq 'DR') {
            $newRecords = @('10.241.32.110')
            Remove-DnsServerResourceRecord -ZoneName "corp.ad.tullib.com" -Name $dnsrecord -RRType "A" -Force
            Write-Host "Record '$dnsrecord' removed in '$env:computername'"
            foreach ($newRecord in $newRecords) {
                Add-DnsServerResourceRecordA -Name $dnsrecord -ZoneName "corp.ad.tullib.com" -IPv4Address $newRecord -TimeToLive $ttl
                Write-Host "Record '$dnsrecord' recreated as A record pointing to '$newRecord' in '$env:computername'"
            }
        } elseif ($Environment -eq 'Prod') {
            $newRecords = @('10.242.32.110', '10.241.32.110')
            Remove-DnsServerResourceRecord -ZoneName "corp.ad.tullib.com" -Name $dnsrecord -RRType "A" -Force
            foreach ($newRecord in $newRecords) {
                Add-DnsServerResourceRecordA -Name $dnsrecord -ZoneName "corp.ad.tullib.com" -IPv4Address $newRecord -TimeToLive $ttl
                Write-Host "Record '$dnsrecord' recreated as A record pointing to '$newRecord' in '$env:computername'"
            }
        }
        Write-Host ""
    }

    foreach ($dc in $domainControllers) {
        Invoke-Command -ComputerName $dc -Credential $cred -ScriptBlock $scriptBlock -ArgumentList $Environment, $dnsrecord, $cred
    }
}
