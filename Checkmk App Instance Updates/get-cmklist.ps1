function get-cmklist {
    [CmdletBinding()]
    param (
    
    )
    
    #$user = 'automation'
    #$pass = 'BYGBHSUBPQUIYPSYVVSV'
    $user = 'wintel'
    $pass = 'Kintaro1212!'
    $CurlPath = "curl.exe"
    $uri = "https://cmk-prod.corp.ad.tullib.com/Main/check_mk/api/1.0/domain-types/host_config/collections/all"

    $Headers = @(
        "Authorization: Bearer $user $pass",
        "accept: application/json"
    )

    Write-Verbose "Getting list of hosts"
    Write-Verbose "API URI: $($uri)"

    try {
        Write-Output "Calling curl.exe..."
        $returnedJSON = & $CurlPath -X GET -s -k -H $Headers $uri
        Write-Output "curl.exe returned: $($returnedJSON)"
        Write-Verbose "Raw JSON response: $($returnedJSON)"
        
        Write-Output "Converting JSON..."
        $data = $returnedJSON | ConvertFrom-Json
        Write-Output "JSON converted successfully."
        Write-Verbose $data   
        return $data.value.id | Where-Object { $_ -notmatch '^pod_' -and $_ -notmatch '_q08_' -and $_ -notmatch '_p10_' -and $_ -notmatch '_p09_'}
    }
    catch {
        Write-Error "Error getting data from API: $($_.Exception.Message)"
        return @{}
    }
}
