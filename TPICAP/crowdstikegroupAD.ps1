function OpenAndReadcomputersFile {
    $filePath = "C:\temp\servers.txt"

    if (-not (Test-Path $filePath)) {
        New-Item -ItemType File -Path $filePath | Out-Null
    }

    $notepadProcess = Start-Process -FilePath "notepad.exe" -ArgumentList $filePath -PassThru
    
    while ($notepadProcess.HasExited -eq $false) {
        Start-Sleep -Seconds 1
    }

    Get-Content -Path $filePath
}


function Add-ComputerToSecurityGroup {
    param (
        [string]$computerName,
        [string]$securityGroupName
    )
    
    try {
        # Attempt to retrieve the computer object to see if it exists and handle any errors
        $computerAD = Get-ADComputer -Identity $computerName -ErrorAction Stop
        try {
            Add-ADGroupMember -Identity $securityGroupName -Members $computerAD -ErrorAction Stop
            Write-Output "Successfully added '$computerName' to security group '$securityGroupName'."
            return $true
        } catch {
            Write-Error "Failed to add '$computerName' to '$securityGroupName': $_"
        }
    } catch {
        Write-Warning "Unable to find an AD computer with the name '$computerName': $_"
    }

    return $false
}

$securityGroup = 'Global_G_GPO_Server_CrowdstrikeAgent'
$computers = OpenAndReadcomputersFile
$addedCount = 0
$missingCount = 0

foreach ($computer in $computers) {
    if (![string]::IsNullOrWhiteSpace($computer)) {
        $result = Add-ComputerToSecurityGroup -computerName $computer -securityGroupName $securityGroup
        if ($result -eq $true) {
            $addedCount++
        } else {
            $missingCount++
        }
    }
}

Write-Host "Summary:"
Write-Host "Computers successfully added to '$securityGroup': $addedCount"
Write-Host "Computers not found in AD: $missingCount"