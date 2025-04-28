$applicationName = "Falcon Identity Protection DC Sensor"
$uninstallPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

# Get uninstall entry
$uninstallKey = Get-ChildItem -Path $uninstallPath | 
                Where-Object { $_.GetValue("DisplayName") -like "*$applicationName*" }

# Extract and format uninstall command with quiet switch
$uninstallString = $uninstallKey.GetValue("UninstallString")
$quietUninstall = if ($uninstallString) { "$uninstallString /qn" }

# Execute silently
if ($quietUninstall) {
    Start-Process "msiexec.exe" -ArgumentList "/X$($uninstallKey.PSChildName) /qn" -Wait
    Write-Host "Uninstallation initiated silently for $applicationName"
}
else {
    Write-Error "Uninstall string not found for $applicationName"
}
