function OpenAndReadServersFile {
    param (
        [String] $filePath = "C:\temp\servers.txt"
    )
    
    Write-Host "Starting to open and read servers file..."
    Add-Content -Path $logFile -Value "[INFO] Starting to open and read servers file..."

    if (-not (Test-Path $filePath)) {
        Write-Host "File not found, creating new file..."
        Add-Content -Path $logFile -Value "[INFO] File not found, creating new file..."
        New-Item -ItemType File -Path $filePath -Force | Out-Null
    } else {
        Write-Host "File exists, opening in Notepad..."
        Add-Content -Path $logFile -Value "[INFO] File exists, opening in Notepad..."
    }

    # Launch and wait for Notepad to exit
    $notepadProcess = Start-Process -FilePath notepad.exe -ArgumentList $filePath -PassThru
    Write-Host "Notepad launched, waiting for close..."
    Add-Content -Path $logFile -Value "[INFO] Notepad launched, waiting for close..."
    $notepadProcess.WaitForExit()

    Write-Host "Notepad closed. Reading content from file..."
    Add-Content -Path $logFile -Value "[INFO] Notepad closed. Reading content from file..."
    return Get-Content -Path $filePath
}

function Send-Email {
    param (
        [String] $subject,
        [String] $body
    )
    Send-MailMessage @emailParams -Subject $subject -Body $body
}



function Get-RemoteSession {
    param (
        [String] $Server
    )
    Write-Host "Getting remote session for $Server..."
    Add-Content -Path $logFile -Value "[INFO] Getting remote session for $Server..."
    
        try {
            $creds = & "D:\Thycotic\Get-thycoticCredentials_V2.ps1" -server $Server
            Write-Host "Using credentials for $($creds.Username) on $server password: $($creds.Password)"
            Add-Content -Path $logFile -Value "[INFO] Using credentials for $($creds.Username) on $server"
            $securePassword = ConvertTo-SecureString $creds.Password -AsPlainText -Force
            $psCred = New-Object System.Management.Automation.PSCredential ($creds.Username, $securePassword)
            $session = New-PSSession -ComputerName $Server -Credential $psCred -ErrorAction Stop
            return $session
        } catch {
            Write-Host "Error: $_"
            Add-Content -Path $logFile -Value "[ERROR] Error: $_"
        }
    
    return $null
}

function Install-CrowdStrikeSensor {
    param (
        [System.Management.Automation.Runspaces.PSSession] $session,
        [String] $Server
    )
    $localInstallerPath = "D:\Patches\Custom\CrowdStrike\WindowsSensor.LionLanner.exe"
    $remotePath = "C:\Temp"
    $remoteInstallerPath = "$remotePath\WindowsSensor.LionLanner.exe"
    $logFile = "C:\Temp\InstallLog.txt"
    
    $fileExists = Invoke-Command -Session $session -ScriptBlock {
        Test-Path -Path "C:\Temp\WindowsSensor.LionLanner.exe"
    }
    
    if (-not $fileExists) {
        Invoke-Command -Session $session -ScriptBlock {
            if (-not (Test-Path -Path "C:\Temp")) {
                New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
                Write-Host "Directory created: C:\Temp"
            }
        }
        try {
            Copy-Item -Path $localInstallerPath -Destination $remoteInstallerPath -ToSession $session -Force -ErrorAction Stop
            Write-Host "Installer copied to $remotePath on $Server"
            Add-Content -Path $logFile -Value "[INFO] Installer copied to $remotePath on $Server"
        } catch {
            Write-Host "Failed to copy installer to $[Server]: $_"
            Add-Content -Path $logFile -Value "[ERROR] Failed to copy installer to $[Server]: $_"
            return $false
        }
    } else {
        Write-Host "Installer already exists on $Server, skipping copy."
        Add-Content -Path $logFile -Value "[INFO] Installer already exists on $Server, skipping copy."
    }
    
    # Execute the installation commands with timeout
    $installationSuccess = Invoke-Command -Session $session -ScriptBlock {
        $installerPath = "C:\Temp\WindowsSensor.LionLanner.exe"
    
        # Start the process
        $process = Start-Process -FilePath $installerPath -ArgumentList "/install /quiet /norestart CID=957CB71205FA45789092911587457C08-52" -PassThru
    
        # Timeout setting (10 minutes)
        $timeout = 10 * 60
        $elapsed = 0
        $interval = 5
    
        while ($true) {
            Start-Sleep -Seconds $interval
            $elapsed += $interval
    
            # Check if the process has exited
            if ($process.HasExited -or $elapsed -ge $timeout) {
                break
            }
        }
    
        if ($elapsed -ge $timeout) {
            try {
                $process.Kill()
            } catch {
                # Handle any errors if process kill fails
                Write-Host "Failed to terminate the process: $_"
            }
            return $false
        }
    
        if ($process.ExitCode -eq 0) {
            # Verify if the csagent process is running
            $csAgentRunning = Get-Process -Name "csagent" -ErrorAction SilentlyContinue
            if ($null -ne $csAgentRunning) {
                return $true
            }
        }
        return $false
    }
    
    return $installationSuccess
    }
    

# Initialize parameters and log file location
$logFile = "C:\Temp\remote_install_log.txt"
$emailParams = @{
    From       = "dennisjeffrey.flores@tpicap.com"
    To         = "servicenow@tpicap.com","dennisjeffrey.flores@tpicap.com"
    SmtpServer = "smtprelay.corp.ad.tullib.com"
}

# Read the list of servers
$servers = OpenAndReadServersFile
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$results = @()

foreach ($server in $servers) {
    if (-not $server) { continue }
    Write-Host "Processing Server: $server"
    Add-Content -Path $logFile -Value "[INFO] Processing [server]: $server"

    $serverstatus = Test-NetConnection $server -ErrorAction SilentlyContinue
    if (-not $serverstatus.RemoteAddress.IPAddressToString) {
        $resultMessage = "Shavlik servers cannot resolve $server`nIT System: Wintel Infrastructure - AM Prod`nRegion: EMEA`nCountries Impacted: London`nAssignment_Group: Global Wintel Server Support`nserver: $server is not resolvable on shavlik servers, please ensure it is resolvable with the proper ip in LDN1WS7001"
        Send-Email -subject "$server not resolvable" -body $resultMessage
        Write-Host "Could not resolve $server"
        Add-Content -Path $logFile -Value "[ERROR]could not resolve $server"
        continue
    }

    $session = Get-RemoteSession -Server $server
    if ($session -is [System.Management.Automation.Runspaces.PSSession]) {
        Write-Host "Session established for $server"
        Add-Content -Path $logFile -Value "[INFO] Session established for $server"

        $serviceStatus = Invoke-Command -Session $session -ScriptBlock {
            $service = Get-Service -Name "csagent" -ErrorAction SilentlyContinue
            switch ($service.Status) {
                'Running'  { Write-Host "Application already running"; return "Running" }
                'Stopped'  { Write-Host "Application is stopped"; return "Stopped" }
                default    { Write-Host "Application is missing"; return "Missing" }
            }
        }

        $connect = Invoke-Command -Session $session -ScriptBlock {
            $result = Test-NetConnection -ComputerName falcon.eu-1.crowdstrike.com -Port 443 -ErrorAction SilentlyContinue
            return $result
        } -ErrorAction SilentlyContinue
        
        
        if ($connect.TcpTestSucceeded) {
            Write-Host "Connection to falcon.eu-1.crowdstrike.com successful from server $server."
            Add-Content -Path $logFile -Value "[INFO] Connection to falcon.eu-1.crowdstrike.com successful from $server."
        } elseif ($connect.TcpTestSucceeded -eq $false) {
            Write-Host "Connection to falcon.eu-1.crowdstrike.com failed."
            Add-Content -Path $logFile -Value "[ERROR] Connection to falcon.eu-1.crowdstrike.com failed from $server $($connect.SourceAddress.IPAddress)"
            $resultMessage = "Connection to falcon.eu-1.crowdstrike.com failed on $server $($connect.SourceAddress.IPAddress) `nIT System: Wintel Infrastructure - AM Prod`nRegion: EMEA`nCountries Impacted: London`nAssignment_Group: Network Operations`nserver: $server cannot establish a connection to the command-and-control console of CrowdStrike. This is needed for application installation"
            Send-Email -subject "Connection to falcon.eu-1.crowdstrike.com failed from $server" -body $resultMessage
            continue
        }elseif ($null -eq $($connect.SourceAddress.IPAddress)) {
            Write-Host "Connection to falcon.eu-1.crowdstrike.com failed."
            Add-Content -Path $logFile -Value "[ERROR] Connection to falcon.eu-1.crowdstrike.com failed from $server $($connect.SourceAddress.IPAddress)."
            $resultMessage = "Connection to falcon.eu-1.crowdstrike.com failed on $server $($connect.SourceAddress.IPAddress)`nIT System: Wintel Infrastructure - AM Prod`nRegion: EMEA`nCountries Impacted: London`nAssignment_Group: Global Wintel Server Support`nserver: $server cannot establish a connection to the command-and-control console of CrowdStrike. This is needed for application installation"
            Send-Email -subject "Connection to falcon.eu-1.crowdstrike.com failed from $server Server cannot resolve the endpoint, please troubleshoot" -body $resultMessage
            continue
        }

        if ($serviceStatus -eq "Missing" -or $serviceStatus -eq "Stopped") { 
            $installationResults = Install-CrowdStrikeSensor -session $session -Server $server
            Write-Host "Installation results for $[server]: $installationResults"
            if ($installationResults -eq $false) { 
                Add-Content -Path $logFile -Value "$server $($connect.SourceAddress.IPAddress) installation failed"
                $resultMessage = "Installation to $server $($connect.SourceAddress.IPAddress) failed `nIT System: Wintel Infrastructure - AM Prod`nRegion: EMEA`nCountries Impacted: London`nAssignment_Group: Global Wintel Server Support: $server cannot establish a connection to the command-and-control console of CrowdStrike. This is needed for application installation"
                Send-Email -subject "Installation to $server $($connect.SourceAddress.IPAddress) failed" -body $resultMessage
                }
            Add-Content -Path $logFile -Value "[INFO] Installation results for $[server]: $installationResults"
        } else {
            Write-Host "Service already running on $server, skipping installation."
            Add-Content -Path $logFile -Value "[INFO] Service already running on $server, skipping installation."
        }

        Remove-PSSession -Session $session
        Write-Host "Closed session for $server"
        Add-Content -Path $logFile -Value "[INFO] Closed session for $server."
    } else {
        Write-Host "Could not establish a session for $server"
        Add-Content -Path $logFile -Value "[ERROR] Could not establish a session for $server $($connect.SourceAddress.IPAddress)"
        $resultMessage = "Shavlik servers cannot connect to $server $($connect.SourceAddress.IPAddress)`nIT System: Wintel Infrastructure - AM Prod`nRegion: EMEA`nCountries Impacted: London`nAssignment_Group: Global Wintel Server Support`nserver: $server connection cannot be established from LDN1WS7001, Please install crowdstrike to this machine manually"
        Send-Email -subject "$server Unable to connect" -body $resultMessage
        continue
    }

    # Log the results
    $results += "Finished processing server $server at $currentDateTime."
}

# Send summary email
$summarySubject = "CrowdStrike Installation Summary - $currentDateTime"
$summaryBody = $results -join "`n"
Send-Email -subject $summarySubject -body $summaryBody

Write-Host "Processing complete. Summary email sent."
Add-Content -Path $logFile -Value "[INFO] Processing complete. Summary email sent at $currentDateTime."


