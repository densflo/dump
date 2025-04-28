# Import logging function from Main_updater.ps1
$logFileName = "Main_updater_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log"
$logFilePath = "C:\Temp\" + $logFileName

function Write-Output {
    param (
        [string]$Message
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$TimeStamp - $Message"
    Add-Content -Path $logFilePath -Value $LogEntry
    Write-Host $Message
}

function set-cmksaveconfig {
    [CmdletBinding()]
    param (
        [string[]]$etag
    )
#$user = 'automation'
#$pass = 'BYGBHSUBPQUIYPSYVVSV'
$CurlPath = "curl.exe"
$uri = "https://cmk-prod.corp.ad.tullib.com/Main/check_mk/api/1.0/domain-types/activation_run/actions/activate-changes/invoke"

# Define the exact headers as they appear in the working curl command
$Headers = @(
    'accept: application/json'
    'Authorization: Bearer Wintel Kintaro1212!'
    'Content-Type: application/json'
    "If-Match: `"$($etag -join ',')`""
)

# Define the body exactly as it appears in the working curl command
$Body = '{
  "redirect": false,
  "sites": [
    "Main"
  ],
  "force_foreign_changes": true
}'

Write-Output "Activating Checkmk changes"
Write-Output "API URI: $($uri)"

try {
    # Make activation request using the exact format that works in curl
    $returnedJSON = & $CurlPath -X POST -s -k $(foreach ($Header in $Headers) {"-H '$Header'"}) -d $Body $uri
    Write-Output "Raw JSON response: $($returnedJSON)"
    
    # Parse JSON response
    $response = $returnedJSON | ConvertFrom-Json
    if (-not $response) {
        throw "Failed to parse API response"
    }

    # Get activation ID from response
    $activationId = $response.id
    if (-not $activationId) {
        Write-Output "Activation ID not found in response. Full response: $($response | ConvertTo-Json -Depth 5)"
        throw "Failed to get activation ID"
    }

    
}
catch {
    Write-Output "Error in activation process: $($_.Exception.Message)"
    Write-Output "Full error details: $_"
    throw
}
}
