$servers = @(
    "ldn1ws7002",
    "ldn1ws7003",
    "ldn2ws7001",
    "ldn2ws7002",
    "ldn2ws7003",
    "sng1ws7001",
    "sng1ws7002",
    "sng2ws7001",
    "syd1ws7001",
    "hkg1ws7001",
    "hkg2ws7001",
    "njc1ws3458",
    "njc2ws3293",
    "njc2ws5323",
    "njc2ws3866",
    "njc1ws7843",
    "njc1ws5465",
    "brz1ws5499"
)

$results = @()

foreach ($server in $servers) {
    try {
        Write-Host "Rebooting $server..."
        Restart-Computer -ComputerName $server -Force -ErrorAction Stop

        Write-Host "Waiting 60 seconds..."
        Start-Sleep -Seconds 60

        $os = Get-CimInstance -ComputerName $server Win32_OperatingSystem -ErrorAction Stop
        $uptime = (Get-Date) - $os.LastBootUpTime

        if ($uptime.TotalMinutes -lt 5) {
            $status = "Rebooted Successfully"
        } else {
            $status = "Reboot Failed (Uptime > 5 minutes)"
        }

        $results += [PSCustomObject]@{
            ServerName = $server
            Uptime     = "{0:N2} minutes" -f $uptime.TotalMinutes
            Status     = $status
        }
    }
    catch {
        Write-Error "Error processing $server: $($_.Exception.Message)"
        $results += [PSCustomObject]@{
            ServerName = $server
            Uptime     = "N/A"
            Status     = "Error: $($_.Exception.Message)"
        }
    }
}

Write-Host "`nSummary:"
$results | Format-Table -AutoSize
