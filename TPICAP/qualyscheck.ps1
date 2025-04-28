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

function Test-RemoteComputer {
    param (
        [String] $Server
    )
    try {
        $ping = Test-Connection -ComputerName $Server -Count 2 -Quiet
        if (-not $ping) {
            throw "Name resolution failed for $Server"
        }
        return $true
    } catch {
        Write-Error $_
        return $false
    }
}

function Get-RemoteSession {
    param (
        [String] $Server
    )
    try {
        $cred = & "D:\Thycotic\Get-thycoticCredentials.ps1" -server $server
        $securePassword = ConvertTo-SecureString $cred.password -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential ($cred.username, $securePassword)

        $session = New-PSSession -ComputerName $server -Credential $psCred -ErrorAction Stop
        return $session
    } catch {
        return $_.Exception.Message
    }
}

$results = @()

foreach ($server in $servers) {
    if (-not $server) {
        continue
    }
    $errorDetails = $null
    $canResolve = Test-RemoteComputer -Server $server

    if (-not $canResolve) {
        $results += [PSCustomObject]@{
            Server = $server
            CanResolve = $false
            SessionEstablished = "Failed"
            Services = "Failed"
            QualysAgent = "Failed"
            NetConnectionTests = "Failed"
            ErrorDetails = "Name resolution failed"
        }
        continue
    }

    $sessionOrError = Get-RemoteSession -Server $server

    if ($sessionOrError -is [System.Management.Automation.Runspaces.PSSession]) {
        $session = $sessionOrError
        try {
            $serviceList = Invoke-Command -Session $session -ScriptBlock { Get-Service | Where-Object { $_.DisplayName -like "*Qualys*" } } -ErrorAction SilentlyContinue
            if ($serviceList) {
                $containsTrendMicroDSM = ($serviceList | Where-Object { $_.Name -eq 'QualysAgent' } | Measure-Object).Count -gt 0
                
            } else {
                $errorDetails = "Failed to query services"
                $containsTrendMicroDSM = $false
                
            }

            # Test-NetConnection logic integrated here
            $testUrls = @("qualysguard.qualys.eu")
            $netConnectionResults = @()

            foreach ($url in $testUrls) {
                $command = "Test-NetConnection -ComputerName $url -Port 443"
                $result = Invoke-Command -Session $session -ScriptBlock { Invoke-Expression $args[0] } -ArgumentList $command
                $netConnectionResults += [PSCustomObject]@{
                    URL = $url
                    IP = $result.RemoteAddress
                    SourceIP = $result.SourceAddress
                    PingSucceeded = $result.PingSucceeded
                    TcpTestSucceeded = $result.TcpTestSucceeded
                }
            }

            Remove-PSSession -Session $session
        } catch {
            $errorDetails = $_.Exception.Message
            $containsTrendMicroDSM = $false
            $netConnectionResults = "Failed"
            $trendMicroOutput = "Error executing Trend Micro command"
        }
    } else {
        $errorDetails = $sessionOrError
        $results += [PSCustomObject]@{
            Server = $server
            CanResolve = $canResolve
            SessionEstablished = $false
            Services = "Failed"
            QualysAgent = "Failed"
            NetConnectionTests = "Failed"
            ErrorDetails = $errorDetails
        }
        continue
    }

    $results += [PSCustomObject]@{
        Server = $server
        CanResolve = $canResolve
        SessionEstablished = $null -ne $session
        Services = if ($serviceList) { $servicelist | Select-Object Status, DisplayName } else { "Failed" }
        QualysAgent = $containsTrendMicroDSM
        
        NetConnectionTests = if($netConnectionResults) {$netConnectionResults | Select-Object URL, IP, TcpTestSucceeded} else {"Test Failed"}
        ErrorDetails = $errorDetails
    }
}

$results | Convert-OutputForCSV | Export-Csv -Path "C:\temp\server_status.csv" -NoTypeInformation
