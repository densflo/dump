# Import required modules
Import-Module "C:\Users\d_flores\OneDrive - TP ICAP\Documents\code\Chekmk-Powershell\CheckMK-PowerShell\CheckMK.psm1" -Force
. 'C:\Users\d_flores\OneDrive - TP ICAP\Documents\Code\Checkmk App Instance Updates\Get-a2rmapp.ps1'
. 'C:\Users\d_flores\OneDrive - TP ICAP\Documents\Code\Checkmk App Instance Updates\get-cmklist.ps1'

# Configuration
$BatchSize = 100
$MaxRetries = 3
$RetryDelay = 30 # seconds
$MemoryCheckInterval = 50 # check memory every N hosts

# Log file setup
$logFileName = "Main_updater_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log"
$logFilePath = "C:\Temp\" + $logFileName

# Memory monitoring
function Get-MemoryUsage {
    $process = Get-Process -Id $PID
    return [math]::Round($process.WorkingSet64 / 1MB, 2)
}

function Invoke-SafeCheckMKOperation {
    param (
        [ScriptBlock]$Operation,
        [string]$OperationName,
        [int]$MaxRetries = 3
    )
    
    $retryCount = 0
    while ($retryCount -lt $MaxRetries) {
        try {
            return & $Operation
        }
        catch {
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                throw "Failed to execute $OperationName after $MaxRetries attempts: $_"
            }
            Write-Output "Retry $retryCount for $OperationName - Error: $_"
            Start-Sleep -Seconds $RetryDelay
        }
    }
}

function Write-Output {
    param (
        [string]$Message
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$TimeStamp - $Message"
    Add-Content -Path $logFilePath -Value $LogEntry
    Write-Host $Message
}

# Connection setup
$cmklist = get-cmklist
$connection = Get-CMKConnection -Hostname "cmk-prod.corp.ad.tullib.com" -Sitename "Main" -Username 'Wintel' -Secret (ConvertTo-SecureString "Kintaro1212!" -AsPlainText -Force)

Write-Output "Starting script execution"
# Process hosts in batches
$totalHosts = $cmklist.Count
$processedHosts = 0
$batchNumber = 1

while ($processedHosts -lt $totalHosts) {
    $batch = $cmklist | Select-Object -First $BatchSize -Skip $processedHosts
    $batchCount = $batch.Count
    
    Write-Output "Processing batch $batchNumber ($batchCount hosts)"
    
    foreach ($cmk in $batch) {
        $processedHosts++
        try {
            # Memory check
            if ($processedHosts % $MemoryCheckInterval -eq 0) {
                $memoryUsage = Get-MemoryUsage
                Write-Output "Memory usage: $memoryUsage MB"
                if ($memoryUsage -gt 1024) {
                    Write-Output "High memory usage detected. Performing garbage collection..."
                    [System.GC]::Collect()
                }
            }

            Write-Output "Processing host: $cmk ($processedHosts of $totalHosts)"
            
            # Get host data with retry logic
            $startTime = Get-Date
            $hostObject = Invoke-SafeCheckMKOperation -Operation {
                Get-CMKHost -HostName $cmk -Connection $connection
            } -OperationName "Get-CMKHost for $cmk" -MaxRetries $MaxRetries

            $endTime = Get-Date
            $timeTaken = ($endTime - $startTime).TotalSeconds
            Write-Output $hostObject

        Write-Output "Get-CMKHost result for host: $cmk - Time taken: $($timeTaken) seconds"
        Write-Output "Calling get-appa2rm for host: $cmk"
        $startTime = Get-Date
        $a2rmData = get-appa2rm -ComputerName $cmk
        $endTime = Get-Date
        $timeTaken = ($endTime - $startTime).TotalSeconds
        Write-Output "get-appa2rm result for host: $cmk - Time taken: $($timeTaken) seconds"
        
        Write-Output "Host object (JSON): $($hostObject | ConvertTo-Json -Depth 5)"

        # Store formatted app:tier pairs
        $appTierPairs = @()
        
        # Process each application entry
        $a2rmData | ForEach-Object {
            $cleanAppName = $_.ApplicationName -replace ':', ' '
            $appTierPair = "$($cleanAppName):$($_.ServiceTier)"
            $appTierPairs += $appTierPair
        }

        # Display unique entries
        Write-Output "Found $($appTierPairs.Count) applications"
        Write-Output "Unique app tier pairs: $($appTierPairs | Select-Object -Unique | ConvertTo-Json -Depth 5)"

        # Clear existing labels
        Write-Output "Clearing existing labels..."
        $labels = $hostObject.extensions.attributes.labels.PSObject.Properties | 
            Where-Object { $_.Value -match '(GOLD|SILVER|BRONZE|TIERZERO|PLATINUM)$' }
        
        Write-Output "Found $($labels.Count) labels to remove"
        if ($labels.Count -gt 0) {
            foreach ($label in $labels) {
                Write-Output "Removing label: $($label.Name) with value: $($label.Value)"
                
                # Get the latest host object before removing the label
                $hostObject = Invoke-SafeCheckMKOperation -Operation {
                    Get-CMKHost -HostName $cmk -Connection $connection
                } -OperationName "Get-CMKHost for $cmk before removing label $($label.Name)"
                
                Invoke-SafeCheckMKOperation -Operation {
                    Remove-CMKHostLabel -HostObject $hostObject -Key $label.Name -Connection $connection
                } -OperationName "Remove-CMKHostLabel for $($label.Name)"
            }
        } else {
            Write-Output "No labels to remove"
        }
        
        # Add new labels
        Write-Output "Adding new labels..."
        Write-Output "App tier pairs: $($appTierPairs | Select-Object -Unique | ConvertTo-Json -Depth 5)"
        $appTierPairs | Select-Object -Unique | ForEach-Object {
            $app, $tier = $_ -split ':'
            if ($app -and $tier) {
                try {
                    Write-Output "Calling Add-CMKHostLabel for app: $($app.Trim()) with tier: $($tier.Trim())"
                    $startTime = Get-Date
                    $hostObject = Invoke-SafeCheckMKOperation -Operation {
                        Get-CMKHost -HostName $cmk -Connection $connection
                    } -OperationName "Get-CMKHost for $cmk" -MaxRetries $MaxRetries
        
                    Invoke-SafeCheckMKOperation -Operation {
                        Add-CMKHostLabel -HostObject $hostObject -Key $app.Trim() -Value $tier.Trim() -Connection $connection
                    } -OperationName "Add-CMKHostLabel for app: $($app.Trim()) with tier: $($tier.Trim()) on server: $cmk"
                    
                    $endTime = Get-Date
                    $timeTaken = ($endTime - $startTime).TotalSeconds
                    Write-Output "Add-CMKHostLabel completed for app: $($app.Trim()) with tier: $($tier.Trim()) - Time taken: $($timeTaken) seconds"
                }
                catch {
                    Write-Warning "Failed to add label for $app : $_"
                }
            }
        }
    } catch {
        Write-Output "Error executing script for server: $_"
    }
}
    
    # Process batch completion
    if ($processedHosts % $BatchSize -eq 0 -or $processedHosts -eq $totalHosts) {
        Write-Output "Processing batch completion for $processedHosts hosts"
        $changes = Invoke-SafeCheckMKOperation -Operation {
            Get-CMKPendingChanges -Connection $connection -Verbose
        } -OperationName "Get-CMKPendingChanges"
        
        if ($changes) {
            Invoke-SafeCheckMKOperation -Operation {
                Invoke-CMKChangeActivation -PendingChanges $changes -ForceForeignChanges -Connection $connection -Verbose
            } -OperationName "Invoke-CMKChangeActivation"
            
            Start-Sleep -Seconds $RetryDelay
        }
    }
} # Close the while loop for batch processing

# Check for remaining hosts and activate changes if necessary
if ($processedHosts % $BatchSize -gt 0) {
    Write-Output "Activating changes for the remaining $($processedHosts % $BatchSize) hosts"
    $changes = Get-CMKPendingChanges -Connection $connection -Verbose
    Invoke-CMKChangeActivation -PendingChanges $changes -ForceForeignChanges -Connection $connection -Verbose
    Start-Sleep -Seconds 180
}
