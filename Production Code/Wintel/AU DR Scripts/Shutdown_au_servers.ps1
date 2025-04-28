function OpenAndReadServersFile {
    $filePath = "C:\temp\servers.txt"

    if (-not (Test-Path $filePath)) {
        New-Item -ItemType File -Path $filePath | Out-Null
    }

    $notepadProcess = Start-Process -FilePath notepad.exe -ArgumentList $filePath -PassThru

    while ($notepadProcess.HasExited -eq $false) {
        Start-Sleep -Seconds 1
    }

    Get-Content -Path $filePath
}

$servers = OpenAndReadServersFile
Import-Module VMware.PowerCLI
$vCenter = "syd1va0001.corp.ad.tullib.com"

$creds = (Get-Credential)
Connect-VIServer -Server $vCenter -Credential $creds -warningaction silentlycontinue -erroraction silentlycontinue

$result = @()

foreach ($server in $servers) {
    try {
        Write-Output "Attempting to shutdown $server gracefully..."
        $vm = Get-VM -Name $server
        if ($vm.PowerState -eq "PoweredOn") {
            Shutdown-VMGuest -VM $vm -Confirm:$false
            $startTime = Get-Date
            while ($vm.PowerState -ne "PoweredOff") {
                Start-Sleep -Seconds 10
                $vm = Get-VM -Name $server # Refresh VM state
                $currentTime = Get-Date
                $elapsedTime = $currentTime - $startTime
                if ($elapsedTime.TotalMinutes -ge 5) {
                    throw "Timed out waiting for $server to shutdown."
                }
            }
            $result += [PSCustomObject]@{
                Server   = $server
                Status   = "Success"
                Message  = "$server shut down successfully."
            }
            Write-Output "$server shut down successfully."
        } else {
            $result += [PSCustomObject]@{
                Server   = $server
                Status   = "Skipped"
                Message  = "$server was already powered off."
            }
            Write-Output "$server was already powered off."
        }
    } catch {
        $result += [PSCustomObject]@{
            Server   = $server
            Status   = "Failed"
            Message  = "Failed to shut down ${server}: $_"
        }
        Write-Warning "Failed to shut down ${server}: $_"
    }
}

Write-Output "Validating final power states..."
foreach ($r in $result) {
    $vm = Get-VM -Name $r.Server
    if ($vm.PowerState -eq "PoweredOff") {
        $r.Status += " (Validated)"
    } else {
        $r.Status = "Failed (Validation Error)"
        $r.Message += " The server is still running."
    }
}

Write-Output "Summary of operations:"
$result | Format-Table -AutoSize
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$result | Export-Csv -Path "C:\temp\Au_server_status_$timestamp.csv"
Disconnect-VIServer -Confirm:$false