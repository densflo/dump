function Get-TrendServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteComputer,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credentials
    )
    
    $services = Invoke-Command -ComputerName $RemoteComputer -Credential $Credentials -ScriptBlock {
        Get-Service -Name "Trend*"
    }

    if ($services) {
        $output = @()
        foreach ($service in $services) {
            $properties = @{
                "Name" = $service.Name
                "DisplayName" = $service.DisplayName
                "Status" = $service.Status
            }
            $output += New-Object PSObject -Property $properties
        }
    }
    else {
        $properties = @{
            "Name" = "None"
            "DisplayName" = "None"
            "Status" = "None"
        }
        $output += New-Object PSObject -Property $properties
    }

    if ($?) {
        return $output
    }
    else {
        $properties = @{
            "Name" = "ERROR"
            "DisplayName" = "ERROR"
            "Status" = "ERROR"
        }
        $output = New-Object PSObject -Property $properties
        return $output
    }
}
