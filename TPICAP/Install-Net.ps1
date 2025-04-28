# Import the required module
Import-Module ServerManager

# List of servers
$servers = @("njc1ws7547")

# Results array
$results = @()

foreach ($server in $servers) {
    Write-Host "Processing server: $server"

    # Try block to catch any errors
    try {
        # Invoke the command on the remote server
        $output = Invoke-Command -ComputerName $server -ScriptBlock {
            Install-WindowsFeature -Name "NET-Framework-Core" -Source "\\10.90.80.243\bulk\sxs"
            # Check if the feature is installed
            $feature = Get-WindowsFeature -Name "NET-Framework-Core"
            return $feature.Installed
        }

        Write-Host "Installation on $server successful. Installed: $output"

        # Add result to the results array
        $results += [PSCustomObject]@{
            ServerName = $server
            Success    = $true
            Installed  = $output
        }
    }
    catch {
        Write-Host "Error on $server. Installation failed."

        # Add error result to the results array
        $results += [PSCustomObject]@{
            ServerName = $server
            Success    = $false
            Installed  = $false
        }
    }

    Write-Host "--------------------------------------------"
}

# Output the results as a table
$results | Format-Table -AutoSize
