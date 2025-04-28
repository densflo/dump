function Switch-TMSDB {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('DR', 'Prod')]
        [String]$Environment
    )

    $dnsRecords = @{
        'DR' = @{
            'syd1lx8001.corp.ad.tullib.com' = '10.241.34.30';
            'syd2lx8001.corp.ad.tullib.com' = '10.241.34.30'
        };
        'Prod' = @{
            'syd1lx8001.corp.ad.tullib.com' = '10.242.34.30';
            'syd2lx8001.corp.ad.tullib.com' = '10.241.34.30'
        }
    }

    $domainControllers = @('SYDPINFDCG01.corp.ad.tullib.com','SYDPINFDCG02.corp.ad.tullib.com','SYDPINFDCG04.corp.ad.tullib.com','LDN1WS0060.corp.ad.tullib.com')
    $ttl = New-TimeSpan -Minutes 1

    $credential = Get-Credential

    foreach ($dc in $domainControllers) {
        $scriptBlock = {
            Param (
                $dnsRecords,
                $Environment,
                $ttl
            )

            try {
                foreach ($recordName in $dnsRecords[$Environment].Keys) {
                    Remove-DnsServerResourceRecord -ZoneName "corp.ad.tullib.com" -Name $recordName.Split('.')[0] -RRType "A" -Force -ErrorAction Stop
                    Add-DnsServerResourceRecordA -Name $recordName.Split('.')[0] -IPv4Address $dnsRecords[$Environment][$recordName] -ZoneName "corp.ad.tullib.com" -TimeToLive $ttl -ErrorAction Stop
                }
            } catch {
                Write-Error "Failed to update DNS records. Error: $_"
            }
        }

        try {
            Invoke-Command -ComputerName $dc -ScriptBlock $scriptBlock -ArgumentList $dnsRecords, $Environment, $ttl -Credential $credential -ErrorAction Stop
        } catch {
            Write-Error "Failed to update DNS records on $dc. Error: $_"
        }
    }
}
