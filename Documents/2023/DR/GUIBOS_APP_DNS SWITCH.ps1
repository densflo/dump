

function Switch-TMSAPP {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('DR', 'Prod')]
        [String]$Environment
    )

    $dnsRecords = @{
        'DR' = @{
            'ultguibos1p.au.icap.com' = '10.241.33.119';
            'sydguibos1p.au.icap.com' = '10.241.33.119'
        };
        'Prod' = @{
            'ultguibos1p.au.icap.com' = '10.241.33.119';
            'sydguibos1p.au.icap.com' = '10.242.33.119'
        }
    }

    $domainControllers = @('SYD1WS0021.au.icap.com', 'SYD2WS0021.au.icap.com')
    $ttl = New-TimeSpan -Minutes 1
    $cred = (Get-Credential)
    foreach ($dc in $domainControllers) {
        try {
            Invoke-Command -ComputerName $dc -Credential $cred -ScriptBlock {
                param($dnsRecords, $Environment, $ttl)
                foreach ($recordName in $dnsRecords[$Environment].Keys) {
                    Remove-DnsServerResourceRecord -ZoneName "au.icap.com" -Name $recordName.Split('.')[0] -RRType "A" -Force -ErrorAction Stop
                    Add-DnsServerResourceRecordA -Name $recordName.Split('.')[0] -IPv4Address $dnsRecords[$Environment][$recordName] -ZoneName "au.icap.com" -TimeToLive $ttl -ErrorAction Stop
                }
            } -ArgumentList $dnsRecords, $Environment, $ttl
        } catch {
            Write-Error "Failed to update DNS records on $dc. Error: $_"
        }
    }
}
