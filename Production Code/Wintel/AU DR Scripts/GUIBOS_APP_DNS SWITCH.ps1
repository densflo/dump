

function Switch-GUIBOSWEB {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('DR', 'Prod')]
        [String]$Environment
    )

    $dnsRecords = @{
        'DR' = @{
            'ultguibos1p.corp.ad.tullib.com' = '10.241.33.119';
            'sydguibos1p.corp.ad.tullib.com' = '10.241.33.119'
        };
        'Prod' = @{
            'ultguibos1p.corp.ad.tullib.com' = '10.241.33.119';
            'sydguibos1p.corp.ad.tullib.com' = '10.242.33.119'
        }
    }

    $domainControllers = @('SYDPINFDCG01.corp.ad.tullib.com', 'SYDPINFDCG02.corp.ad.tullib.com','SYDPINFDCG04.corp.ad.tullib.com','LDN1WS0060.corp.ad.tullib.com','LDN1WS9995.corp.ad.tullib.com')
    $ttl = New-TimeSpan -Minutes 1
    $cred = (Get-Credential)
    foreach ($dc in $domainControllers) {
        try {
            Invoke-Command -ComputerName $dc -Credential $cred -ScriptBlock {
                param($dnsRecords, $Environment, $ttl)
                foreach ($recordName in $dnsRecords[$Environment].Keys) {
                    Remove-DnsServerResourceRecord -ZoneName "corp.ad.tullib.com" -Name $recordName.Split('.')[0] -RRType "A" -Force -ErrorAction Stop
                    Add-DnsServerResourceRecordA -Name $recordName.Split('.')[0] -IPv4Address $dnsRecords[$Environment][$recordName] -ZoneName "au.icap.com" -TimeToLive $ttl -ErrorAction Stop
                }
            } -ArgumentList $dnsRecords, $Environment, $ttl
        } catch {
            Write-Error "Failed to update DNS records on $dc. Error: $_"
        }
    }
}
