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
    try {
        Write-Output "Attempting to power on $server..."
        $vm = Get-VM -Name $server
        if ($vm.PowerState -eq "PoweredOff") {
            Start-VM -VM $vm -Confirm:$false
            Start-Sleep -Seconds 10 # Giving some time for the operation to be initiated
            $vm = Get-VM -Name $server # Refresh VM state
            if ($vm.PowerState -eq "PoweredOn") {
                $result += [PSCustomObject]@{
                    Server   = $server
                    Status   = "Success"
                    Message  = "$server powered on successfully."
                }
                Write-Output "$server powered on successfully."
            } else {
                throw "$server failed to power on."
            }
        } else {
            $result += [PSCustomObject]@{
                Server   = $server
                Status   = "Skipped"
                Message  = "$server was already powered on."
            }
            Write-Output "$server was already powered on."
        }
    } catch {
        $result += [PSCustomObject]@{
            Server   = $server
            Status   = "Failed"
            Message  = "Failed to power on ${server}: $_"
        }
        Write-Warning "Failed to power on ${server}: $_"
    }
}

Write-Output "Summary of operations:"
$result | Format-Table -AutoSize