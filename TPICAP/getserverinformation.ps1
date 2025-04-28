# Import VMware PowerCLI module
Import-Module VMware.PowerCLI

# Connect to your vCenter or ESXi host
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
$vcUser = "CORP\dflores-a"
$vcPassword = "F9gLPf*%Ljgf8mT"
$vcServer = "njc2va0001.corp.ad.tullib.com"
$creds = New-Object System.Management.Automation.PSCredential($vcUser, ($vcPassword | ConvertTo-SecureString -AsPlainText -Force))
Connect-VIServer -Server $vcServer -Credential $creds

# Read server list
$servers = Get-Content "C:\temp\serverslist.txt"

# Initialize result array
$results = @()

# Loop through servers and get info
foreach ($server in $servers) {
    $vm = Get-VM -Name $server -ErrorAction SilentlyContinue

    if ($vm) {
        $vmHost = Get-VMHost -VM $vm
        $vmHostHardware = Get-VMHostHardware -VMHost $vmHost
        $vmGuest = Get-VMGuest -VM $vm

        $result = [PSCustomObject]@{
            ServerName     = $server
            CPU_Cores      = $vm.NumCpu
            Memory_GB      = [math]::Round($vm.MemoryGB, 2)
            DiskInfo       = ($vm.ExtensionData.Config.Hardware.Device | Where-Object { $_.GetType().Name -eq "VirtualDisk" } | ForEach-Object { "Size: $([math]::Round($_.CapacityInKB * 1KB / 1GB, 2))GB" }) -join '; '
            OS_Version     = $vmGuest.OSFullName
            Host_Model     = $vmHostHardware.SystemInfo.Model
            Host_CPU_Model = $vmHostHardware.CpuInfo.Model
            Host_CPU_Cores = $vmHostHardware.CpuInfo.NumCpuCores
            Host_Memory_GB = [math]::Round($vmHostHardware.MemoryInfo.PhysicalMemory / 1GB, 2)
        }
    } else {
        $result = [PSCustomObject]@{
            ServerName     = $server
            Message        = "Server not found in vCenter"
        }
    }

    $results += $result
}

# Export results to CSV
$results | Export-Csv -Path "C:\temp\ServerInfo.csv" -NoTypeInformation
$results | Format-Table -AutoSize

# Disconnect from vCenter
Disconnect-VIServer -Server $vcServer -Confirm:$false
