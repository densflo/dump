# Define the path to the file containing server names
$file = "C:\temp\list.txt"

# Initialize an array to store server details
$servers = @()

# Read each server name from the file
Get-Content $file | ForEach-Object {
    $serverName = $_
    
    Write-Host "Resolving server: $serverName"

    # Initialize variables to hold server details, assume unresolvable initially
    $ipAddress = "Unresolvable"
    $fqdn = "N/A"
    $shortName = "N/A"
    
    # Attempt to resolve the IP address of the server using try-catch
    try {
        $ipAddressTmp = [System.Net.Dns]::GetHostAddresses($serverName) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 -ExpandProperty IPAddressToString
        if ($ipAddressTmp) {
            $ipAddress = $ipAddressTmp
            Write-Host "  IP Address found: $ipAddress $serverName"
            # Since IP was resolved, get FQDN and short name
            $fqdn = [System.Net.Dns]::GetHostEntry($serverName).HostName
            $shortName = $fqdn -replace "\..*"
        }
    } catch {
        # Catch block executes if there's an exception (e.g., server name cannot be resolved)
        Write-Host "  Unable to resolve IP address for $serverName"
    }
    
    # Add server details to the array
    $servers += [PSCustomObject]@{
        IP        = $ipAddress
        FQDN      = $fqdn
        ShortName = $shortName
    }
}

# Display the results in a table
$servers | Format-Table -AutoSize