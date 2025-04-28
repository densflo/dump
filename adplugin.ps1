# Check if DC role is installed
if (-not (Get-Command dcdiag -ErrorAction SilentlyContinue)) {
  Write-Host "3 AD_Checks - dcdiag not found. Server is likely not a domain controller."
  exit
}

# AD Connectivity Test
$connectivityOutput = dcdiag /test:connectivity /s:$env:COMPUTERNAME
if ($connectivityOutput -match "passed test Connectivity") {
  $connectivityStatus = 0
  $connectivityMessage = "AD_Connectivity - Connectivity test passed"
} else {
  $connectivityStatus = 2
  $connectivityMessage = "AD_Connectivity - Connectivity test failed"
}
Write-Host "$connectivityStatus $connectivityMessage | $connectivityOutput"

# AD Advertising Test
$advertisingOutput = dcdiag /test:advertising /s:$env:COMPUTERNAME
if ($advertisingOutput -match "passed test Advertising") {
  $advertisingStatus = 0
  $advertisingMessage = "AD_Advertising - Advertising test passed"
} else {
  $advertisingStatus = 2
  $advertisingMessage = "AD_Advertising - Advertising test failed"
}
Write-Host "$advertisingStatus $advertisingMessage | $advertisingOutput"
