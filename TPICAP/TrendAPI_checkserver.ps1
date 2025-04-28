# Set your API key and endpoint
$api_key = "YOUR_API_KEY"
$api_endpoint = "YOUR_API_ENDPOINT"
$headers = @{
    "api-key" = $api_key;
    "api-version" = "v1";
    "Content-Type" = "application/json";
}

# Get the agent ID associated with the computer you want to check
$ipAddress = "YOUR_IP_ADDRESS"
$macAddress = "YOUR_MAC_ADDRESS"
$uri = "$api_endpoint/api/computers/search"
$searchBody = @{
    "searchCriteria" = @(
        @{
            "fieldName" = "hostName";
            "stringTest" = "equal";
            "stringValue" = $ipAddress;
        },
        @{
            "fieldName" = "MAC";
            "stringTest" = "equal";
            "stringValue" = $macAddress;
        }
    )
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method 'POST' -Body $searchBody
$agentID = $response.computers[0].ID

# Get the agent status
$agentUri = "$api_endpoint/api/agents/$agentID"
$agentResponse = Invoke-RestMethod -Uri $agentUri -Headers $headers -Method 'GET'
$agentStatus = $agentResponse.computerStatus

# Check if the agent is reporting to the console
if ($agentStatus -eq "online") {
    Write-Host "The agent is reporting to the console" -ForegroundColor Green
} else {
    Write-Host "The agent is NOT reporting to the console" -ForegroundColor Red
}
