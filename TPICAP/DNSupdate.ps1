function Update-DnsAliases {
    param (
        [hashtable]$DnsServers
    )

    # Define the DNS aliases to be removed and added
    $dnsChanges = @{
        "Remove" = @(
            @{
                "Zone" = "us.icap.com";
                "Aliases" = @("ptlm2", "drptlm2");
            },
            @{
                "Zone" = "corp.ad.tullib.com";
                "Aliases" = @("ptlm2", "drptlm2");
            }
        );

        "Add" = @(
            @{
                "Zone" = "us.icap.com";
                "Aliases" = @{
                    "ptlm2" = "njc1lx2270.corp.ad.tullib.com";
                    "drptlm2" = "njc2lx0696.corp.ad.tullib.com";
                }
            },
            @{
                "Zone" = "corp.ad.tullib.com";
                "Aliases" = @{
                    "ptlm2" = "njc1lx2270.corp.ad.tullib.com";
                    "tmsptlm" = "njc1lx2270.corp.ad.tullib.com";
                    "us02ucrkgsw02p" = "njc1lx2270.corp.ad.tullib.com";
                    "drptlm2" = "njc2lx0696.corp.ad.tullib.com";
                    "drtmsptlm" = "njc2lx0696.corp.ad.tullib.com";
                    "us03ucrkgsw02p" = "njc2lx0696.corp.ad.tullib.com";
                }
            }
        );
    }

    # Remove DNS aliases
    foreach ($change in $dnsChanges.Remove) {
        $zone = $change.Zone
        $dnsServer = $DnsServers[$zone].PDC
        $credential = $DnsServers[$zone].Credential

        foreach ($alias in $change.Aliases) {
            Remove-DnsServerResourceRecord -ZoneName $zone -RRType "CNAME" -Name $alias -ComputerName $dnsServer -Force -Credential $credential
        }
    }

    # Add new DNS aliases
    foreach ($change in $dnsChanges.Add) {
        $zone = $change.Zone
        $dnsServer = $DnsServers[$zone].PDC
        $credential = $DnsServers[$zone].Credential

        foreach ($alias in $change.Aliases.Keys) {
            $target = $change.Aliases[$alias]
            Add-DnsServerResourceRecordCName -ZoneName $zone -Name $alias -HostNameAlias $target -ComputerName $dnsServer -Credential $credential
        }
    }
}

$DnsServers = @{
    "us.icap.com" = @{
        "PDC" = "PDC_for_us.icap.com";
        "Credential" = (Get-Credential -Message "Enter credentials for us.icap.com PDC")
    };
    "corp.ad.tullib.com" = @{
        "PDC" = "PDC_for_corp.ad.tullib.com";
        "Credential" = (Get-Credential -Message "Enter credentials for corp.ad.tullib.com PDC")
    };
}

Update-DnsAliases -DnsServers $DnsServers

function Dns-Failover {
    param (
        [hashtable]$DnsServers
    )

    # Define the DNS aliases to be removed and added
    $dnsChanges = @{
        "us.icap.com" = @{
            "Remove" = @("ptlm2");
            "Add" = @{
                "ptlm2" = "njc2lx0696.corp.ad.tullib.com";
            }
        };
        "corp.ad.tullib.com" = @{
            "Remove" = @("ptlm2");
            "Add" = @{
                "ptlm2" = "njc2lx0696.corp.ad.tullib.com";
            }
        }
    }

    # Update DNS aliases
    foreach ($zone in $dnsChanges.Keys) {
        $dnsServer = $DnsServers[$zone].PDC
        $credential = $DnsServers[$zone].Credential

        # Remove aliases
        foreach ($alias in $dnsChanges[$zone].Remove) {
            Remove-DnsServerResourceRecord -ZoneName $zone -RRType "CNAME" -Name $alias -ComputerName $dnsServer -Force -Credential $credential
        }

        # Add aliases
        foreach ($alias in $dnsChanges[$zone].Add.Keys) {
            $target = $dnsChanges[$zone].Add[$alias]
            Add-DnsServerResourceRecordCName -ZoneName $zone -Name $alias -HostNameAlias $target -ComputerName $dnsServer -Credential $credential
        }
    }
}

Dns-Failover -DnsServers $DnsServers

function Dns-Failback {
    param (
        [hashtable]$DnsServers
    )

    # Define the DNS aliases to be removed and added
    $dnsChanges = @{
        "us.icap.com" = @{
            "Remove" = @("ptlm2");
            "Add" = @{
                "ptlm2" = "njc1lx2270.corp.ad.tullib.com";
            }
        };
        "corp.ad.tullib.com" = @{
            "Remove" = @("ptlm2");
            "Add" = @{
                "ptlm2" = "njc1lx2270.corp.ad.tullib.com";
            }
        }
    }

    # Update DNS aliases
    foreach ($zone in $dnsChanges.Keys) {
        $dnsServer = $DnsServers[$zone].PDC
        $credential = $DnsServers[$zone].Credential

        # Remove aliases
        foreach ($alias in $dnsChanges[$zone].Remove) {
            Remove-DnsServerResourceRecord -ZoneName $zone -RRType "CNAME" -Name $alias -ComputerName $dnsServer -Force -Credential $credential
        }

        # Add aliases
        foreach ($alias in $dnsChanges[$zone].Add.Keys) {
            $target = $dnsChanges[$zone].Add[$alias]
            Add-DnsServerResourceRecordCName -ZoneName $zone -Name $alias -HostNameAlias $target -ComputerName $dnsServer -Credential $credential
        }
    }
}

Dns-Failback -DnsServers $DnsServers

function Dns-Confirm {
    param (
        [hashtable]$DnsServers
    )

    # Define the DNS aliases to be checked
    $dnsAliases = @{
        "us.icap.com" = @("ptlm2", "drptlm2");
        "corp.ad.tullib.com" = @("ptlm2", "tmsptlm", "us02ucrkgsw02p", "drptlm2", "drtmsptlm", "us03ucrkgsw02p");
    }

    # Check and display DNS records
    foreach ($zone in $dnsAliases.Keys) {
        $dnsServer = $DnsServers[$zone].PDC
        $credential = $DnsServers[$zone].Credential

        Write-Host "DNS Records for zone: $zone"
        foreach ($alias in $dnsAliases[$zone]) {
            $record = Get-DnsServerResourceRecord -ZoneName $zone -RRType "CNAME" -Name $alias -ComputerName $dnsServer -Credential $credential
            if ($record) {
                Write-Host "Alias: $($record.HostName) Target: $($record.RecordData.HostNameAlias)"
            } else {
                Write-Host "Alias: $alias not found"
            }
        }
        Write-Host ""
    }
}

$DnsServers = @{
    "us.icap.com" = @{
        "PDC" = "PDC_for_us.icap.com";
        "Credential" = (Get-Credential -Message "Enter credentials for us.icap.com PDC")
    };
    "corp.ad.tullib.com" = @{
        "PDC" = "PDC_for_corp.ad.tullib.com";
        "Credential" = (Get-Credential -Message "Enter credentials for corp.ad.tullib.com PDC")
    };
}

Dns-Confirm -DnsServers $DnsServers
