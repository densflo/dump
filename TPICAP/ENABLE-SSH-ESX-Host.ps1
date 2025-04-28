# Open 'C:\Input\input.txt' in Notepad
$notepad = Start-Process 'notepad.exe' 'E:\input.txt' -PassThru

# Wait for the Notepad process to exit before proceeding
$notepad.WaitForExit()

# Load the VMware automation module
Import-Module VMware.VimAutomation.Core

# Prompt user for credentials
#$cred = Get-Credential

# Connect to the VMware vSphere server
#Connect-VIServer -Server 'njcesxvsvc01.na.ad.tullib.com' -Credential $cred -AllLinked


# Read the list of servers from 'C:\Input\input.txt'
$servers = Get-Content 'E:\input.txt'
$results = @()
# Loop through each server to start the SSH service
foreach ($server in $servers) {
    try {
        # Initially attempt to resolve and get the VMHost by the short name
        $esxiHost = Get-VMHost -Name $server -ErrorAction Stop
    }
    catch {
        # If an error occurs, attempt to resolve to the FQDN and retry
        $FQDN = [net.dns]::GetHostEntry($server).Hostname
        $esxiHost = Get-VMHost -Name $FQDN
    }
    
    if ($esxiHost) {
        $sshService = Get-VMHostService -VMHost $esxiHost | Where-Object { $_.Key -eq "TSM-SSH" }
        Start-VMHostService -HostService $sshService -Confirm:$false
        $sshService = Get-VMHostService -VMHost $esxiHost | Where-Object {$_.Key -eq "TSM-SSH"}
    
    # Accumulate results in an array
    $results += New-Object PSObject -Property @{
        'Host' = $esxiHost.Name
        'SSH Service Running' = $sshService.Running
        'SSH Service Policy' = $sshService.Policy
    }
    }
}

# Initialize an array to hold results

# Output the results in a formatted table
$results | Format-Table -AutoSize
