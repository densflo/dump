function Get-ApplicationsBySearchString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$RemoteComputerName,
        [Parameter(Mandatory)]
        [System.Management.Automation.Credential()]
        $Credentials,
        [Parameter(Mandatory)]
        [string]$SearchString
    )
    
    $session = New-PSSession -ComputerName $RemoteComputerName -Credential $Credentials
    
    $scriptBlock = {
        param (
            [Parameter(Mandatory)]
            [string]$SearchString
        )
        
        # Get the uninstall registry key hive
        $uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

        # Get the uninstall registry key wow6432 node
        $uninstallWow6432Node = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

        # Get all the subkeys in the uninstall registry key hive
        $subKeys = Get-ChildItem -Path $uninstallKey | Where-Object { $_.Property -contains "DisplayName" }

        # Get all the subkeys in the uninstall registry key wow6432 node
        $subKeysWow6432Node = Get-ChildItem -Path $uninstallWow6432Node | Where-Object { $_.Property -contains "DisplayName" }

        # Combine the subkeys from both the hive and wow6432 node
        $subKeys += $subKeysWow6432Node

        $applications = @()
        # Loop through all the subkeys and check if the DisplayName value contains the search string
        foreach ($subKey in $subKeys) {
            $displayName = $subKey.GetValue("DisplayName")
            if ($displayName -match $SearchString) {
                $applications += $displayName
            }
        }

        if ($applications.Count -eq 0) {
            return 'None'
        } else {
            return $applications
        }
    }

    $applications = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $SearchString

    Remove-PSSession -Session $session

    return $applications
}
