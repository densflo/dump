function Get-A2RMData {
   
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [string]$ComputerName = $env:computername,
        [string]$CurlPath = "curl.exe"
    )

    try {
        # Validate computer name
        if ([string]::IsNullOrEmpty($ComputerName)) {
            throw "Computer name cannot be empty"
        }

        Write-Verbose "Processing for hostname: $ComputerName"

        # Set up API call
        $user = 'readonly'
        $pass = 'readonly'
        $pair = "$($user):$($pass)"
        $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
        $Headers = "Authorization:Basic $encodedCreds"

        # Make API calls
        $uri = "https://api.a2rm.direct.tpicapcloud.com/host/$($ComputerName)?report=hostcache"
        $deviceUri = "https://api.a2rm.tpicapcloud.com/device/hosts?name=$($ComputerName)"

        Write-Verbose "Making API call to A2RM host"
        $returnedJSON = & $CurlPath -X GET -s -k -H $Headers $uri
        
        if (-not $?) {
            throw "Curl command failed for host API. Check network connection and try running manually for full output."
        }
        $A2RMData = $returnedJSON | ConvertFrom-Json

        Write-Verbose "API call to A2RM host successful"

        Write-Verbose "Making API call to A2RM device/host"
        
        $deviceJSON = & $CurlPath -X GET -s -k -H $Headers $deviceUri
        if (-not $?) {
            throw "Curl command failed for device/host API. Check network connection and try running manually for full output."
        }
        $deviceData = $deviceJSON | ConvertFrom-Json
        Write-Verbose "API call to A2RM device/host successful"
        
       
            Write-Verbose "Raw JSON Payload (Host: $($ComputerName)):"
            Write-Verbose $returnedJSON
            Write-Verbose "`nRaw JSON Payload (Device):$($ComputerName)"
            Write-Verbose $deviceJSON
            Write-Verbose "`n----------------------------------------"

        
        # Format and display the data
        Write-Output "`nA2RM Data for $($A2RMData.Hostname.ToUpper())"
        Write-Output "----------------------------------------"
        
        # Display basic information
        Write-Output "Basic Information:"
        Write-Output "  Hostname: $($A2RMData.Hostname)"
        Write-Output "  Environment: $($A2RMData.'Derived-Environment')"
        Write-Output "  OS Type: $($A2RMData.'OS-Type')"
        Write-Output "  Location: $($A2RMData.Location)"
        Write-Output "  Lifecycle Stage: $($A2RMData.'Lifecycle-Stage')"
        Write-Output "  In Service: $($A2RMData.'In Service')"
        
        # Display Application Instances
        Write-Output "`nApplication Instances:"
        if ($A2RMData.'Application-Instances'.Count -gt 0) {
            foreach ($instance in $A2RMData.'Application-Instances') {
                $appName = $instance.PSObject.Properties.Name
                $appData = $instance.PSObject.Properties.Value
                
                Write-Output "  Application: $appName"
                Write-Output "    Environment: $($appData.Environment)"
                Write-Output "    Region: $($appData.Region)"
                Write-Output "    Service Tier: $($appData.'Service-Tier')"
                Write-Output "    Lifecycle Stage: $($appData.'Lifecycle-Stage')"
                Write-Output "    APM Enabled: $($appData.'APM-Enabled')"
                 Write-Output "    Description: $($appData.Description)"
                Write-Output "    Business Owner: $($appData.'Business-Owner')"
                Write-Output "    Technical Owner: $($appData.'Technical-Owner')"
                Write-Output "    Support Owner: $($appData.'Support-Owner')"
                Write-Output "    Support Team: $($appData.'Support-Team')"
                Write-Output ""
            }
        } else {
            Write-Output "  No applications found"
        }
        
        # Display Server Information
        Write-Output "`nServer Information:"
        Write-Output "  Server Hierarchy: $($A2RMData.'Server-Hierarchy')"
        Write-Output "  APM Enabled: $($A2RMData.'APM-Enabled')"
        Write-Output "  DB Server: $($A2RMData.'DB-Server')"
        Write-Output "  AppD Agent Port1: $($A2RMData.'Appd-Agent-Port1')"
        Write-Output "  AppD Agent Port2: $($A2RMData.'Appd-Agent-Port2')"
        
        # Display Tags
        Write-Output "`nTags:"
        Write-Output "  Name: $($A2RMData.'Tag:Name')"
        Write-Output "  Hostname: $($A2RMData.'Tag:Hostname')"
        
        Write-Output "`n----------------------------------------"

        # New API call for device/host
        Write-Output "`nDevice Host Data:"
        if ($deviceData.$ComputerName) {
            $device = $deviceData.$ComputerName
            foreach ($key in $device.PSObject.Properties) {
                if (-not ([string]::IsNullOrEmpty($key.Value)) -and $key.Value -ne "UNKNOWN" -and $key.Value -ne "None") {
                    Write-Output "  $($key.Name) : $($key.Value)"
                }
            }
        } else {
            Write-Output "  No device host data found for $($ComputerName)"
        }
        Write-Output "`n----------------------------------------"
    }
    catch {
        Write-Error $_.Exception.Message
    }
}
