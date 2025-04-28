# Search for Trend Micro Deep Security Agent and uninstall it
$agent = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*Trend Micro Deep Security Agent*"}
if ($agent) {
    $uninstall = $agent.Uninstall()
    if ($uninstall.ReturnValue -eq 0) {
        Write-Host "Trend Micro Deep Security Agent has been uninstalled."
    } else {
        Write-Host "An error occurred while attempting to uninstall Trend Micro Deep Security Agent."
    }
} else {
    Write-Host "Trend Micro Deep Security Agent was not found on this computer."

}

# Copy the MSI file to the destination location if found in any of the source locations
$sourceLocations = "\\10.90.80.93\patches`$\Custom\Trend\", "\\10.182.32.37\patches`$\Custom\Trend\", "\\10.202.33.43\patches`$\Custom\Trend\"
$destinationLocation = "C:\temp"

if (!(Test-Path $destinationLocation)) {New-Item -ItemType Directory -Path $destinationLocation | Out-Null}

foreach ($location in $sourceLocations) {
    $file = Join-Path $location "Agent-Core-Windows.msi"
    if (Test-Path $file) {Copy-Item $file $destinationLocation; break}
}

# Install the MSI file and check if it was installed
if (Test-Path (Join-Path $destinationLocation "Agent-Core-Windows.msi")) {
    Write-Host "File successfully copied to $destinationLocation"
    $msiPath = Join-Path $destinationLocation "Agent-Core-Windows.msi"
    Write-Host "Installing MSI file..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn" -Wait
    $msiProductCode = (Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*Trend Micro Deep Security Agent*"}).IdentifyingNumber
    if ($msiProductCode) {
        Write-Host "MSI file is installed with product code '$msiProductCode'."
    } else {
        Write-Host "MSI file is not installed."
        exit 1
    }
} else {
    Write-Host "File not found in source locations"
    return $true
    exit 1
}

if (!(Test-Path $cmdPath)) {
    Write-Error "The dsa_control.cmd file '$cmdPath' does not exist."
    exit 1
}

Write-Host "Running dsa_control.cmd..."
& "C:\Program Files\Trend Micro\Deep Security Agent\dsa_control.cmd" -a "dsm://agents.workload.gb-1.cloudone.trendmicro.com:443/" "tenantID:BE123086-1CAA-5C3A-2027-3BCB78B797A6" "token:9BA0BFE0-65DE-2658-82BB-2AD32ED43100" "policyid:562"

