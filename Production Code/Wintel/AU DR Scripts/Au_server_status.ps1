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
$user = "CORP\dflores-a"
$pass = ConvertTo-SecureString -String "Ol&q&tDT2C)XRz@" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($user, $pass)
Connect-VIServer -Server $vCenter -Credential $creds -warningaction silentlycontinue -erroraction silentlycontinue

$result = @()

foreach ($server in $servers) {
    $vm = Get-VM -Name $server
    if ($null -ne $vm) {
        $networks = $vm | Get-NetworkAdapter
        
        # Initialize an empty array to hold network statuses
        $networkStatuses = @()
        foreach ($network in $networks) {
            # Check if the network is connected
            $networkStatus = if ($network.ExtensionData.Connectable.Connected) { "Connected" } else { "Disconnected" }
            $networkDetail = "$($network.Name): $($networkStatus)"
            # Add the detailed network status to our array
            $networkStatuses += $networkDetail
        }

        # Combine all network statuses into a single string 
        $allNetworkStatuses = $networkStatuses -join ', '
        # Retrieve the OS version
        $osVersion = $vm.Guest.OSFullName

        $result += [PSCustomObject]@{
            Server        = $server
            PowerState    = $vm.PowerState
            NetworkStatus = $allNetworkStatuses
            OSVersion     = $osVersion
        }
    } else {
        $result += [PSCustomObject]@{
            Server        = $server
            PowerState    = "VM not found"
            NetworkStatus = "N/A"
            OSVersion     = "N/A"
        }
    }
}

Write-Output "VM Status Report:"
$result | Format-Table -AutoSize
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$result | Export-Csv -Path "C:\temp\Au_server_status_$timestamp.csv"
Disconnect-VIServer -Confirm:$false