function Invoke-SwitchGubiosDNS {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('DR', 'Prod')]
        [string]$Environment
    )

     $domainControllers = @(
        'SNGPINFDCA02.global.icap.com',
        'HK00WDSSAPP03P.global.icap.com',
        'HK00WDSSAPP04P.global.icap.com',
        'LDN1WS0356.global.icap.com',
        'LDN2WS0279.global.icap.com',
        'SYD2WS0020.global.icap.com',
        'SYD1WS0020.global.icap.com'
    )
    
    $cred = Get-Credential
    
    Invoke-Command -ComputerName $domainControllers -Credential $cred -ArgumentList $Environment -ScriptBlock {
        param (
            [Parameter(Mandatory=$true)]
            [ValidateSet('DR', 'Prod')]
            [string]$Environment
        )

        $DNSRecordsProd = @{
            'AU00WGUIBKK01P' = 'AU00WGUIAPP01P.global.icap.com'
            'AU00WGUIHKG01P' = 'AU00WGUIAPP02P.global.icap.com'
            'AU00WGUIJAK01P' = 'AU00WGUIAPP03P.global.icap.com' 
            'AU00WGUIMLA01P' = 'AU00WGUIAPP04P.global.icap.com' 
            'AU00WGUISNG01P' = 'AU00WGUIAPP06P.global.icap.com' 
            'AU00WGUISYD01P' = 'AU00WGUIAPP07P.global.icap.com' 
            'AU00WGUITCM01P' = 'AU00WGUIAPP08P.global.icap.com'
        }

        $DNSRecordsDR = @{
            'AU00WGUIBKK01P' = 'AU01WGUIAPP01P.global.icap.com'
            'AU00WGUIHKG01P' = 'AU01WGUIAPP02P.global.icap.com'
            'AU00WGUIJAK01P' = 'AU01WGUIAPP03P.global.icap.com' 
            'AU00WGUIMLA01P' = 'AU01WGUIAPP04P.global.icap.com' 
            'AU00WGUISNG01P' = 'AU01WGUIAPP06P.global.icap.com' 
            'AU00WGUISYD01P' = 'AU01WGUIAPP07P.global.icap.com' 
            'AU00WGUITCM01P' = 'AU01WGUIAPP08P.global.icap.com'
        }

        $DNSRecords = @(
            'AU00WGUIBKK01P',
            'AU00WGUIHKG01P',
            'AU00WGUIJAK01P',
            'AU00WGUIMLA01P',
            'AU00WGUISNG01P',
            'AU00WGUISYD01P',
            'AU00WGUITCM01P'
        )


        $ttl = New-TimeSpan -Minutes 1
        Write-Host "Domain Controller: $env:COMPUTERNAME"
        Write-Host "---------------------------------"

        foreach ($record in $DNSRecords) {
            if ($Environment -eq 'DR') {
                $newRecord = $DNSRecordsDR[$record]
            } elseif ($Environment -eq 'Prod') {
                $newRecord = $DNSRecordsProd[$record]
            }

            Remove-DnsServerResourceRecord -ZoneName "global.icap.com" -RRType "CNAME" -Name "$record" -ComputerName $env:COMPUTERNAME -Force
            Add-DnsServerResourceRecordCName -Name "$record" -ZoneName "global.icap.com" -ComputerName $env:COMPUTERNAME -HostNameAlias $newRecord -TimeToLive $ttl
            Write-Host "Record '$record' recreated as CNAME pointing to '$newRecord'"
        }

        Write-Host ""
    }
}


