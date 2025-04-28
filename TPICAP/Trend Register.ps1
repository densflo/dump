
function Check-ApexAndRunScut ($session) {
    $result = Invoke-Command -Session $session -ScriptBlock {
        $outputFile = "C:\temp\trend\A1\output.txt" # File to capture output
        $uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $uninstallWow6432Node = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $subKeys = Get-ChildItem -Path $uninstallKey 
        $subKeysWow6432Node = Get-ChildItem -Path $uninstallWow6432Node
        $subKeys += $subKeysWow6432Node
        $apexInstalled = $false # Initialize flag for Apex installation

        foreach ($subKey in $subKeys) {
            $displayName = $subKey.GetValue("DisplayName")
            if ($displayName -like "*Apex*") {
                $apexInstalled = $true
                Write-Host "$env:COMPUTERNAME has Apex installed# Apex is installed"
                Start-Process -FilePath 'C:\temp\trend\A1\scut.exe' -ArgumentList "-noinstall" -RedirectStandardOutput $outputFile -Wait
            }
        }
        
        # Fetch the output from the file
        if (Test-Path $outputFile) {
            $output = Get-Content $outputFile -Raw
            Write-Host "Output from scut.exe: $output"
        }
        
        $outputObj = [PSCustomObject]@{
            IsApexInstalled = $apexInstalled
            Output = $output
        }
        
        return $outputObj
    }

    # Display the output locally, fetched from the remote machine
    Write-Host "Remote Output: $($result.Output)"
    return $result
}



function InstallOrUpdateTrend ($session) {
    Invoke-Command -Session $session -ScriptBlock {
        $subKeys = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" 
        foreach ($subKey in $subKeys) {
            if (($subKey.GetValue("displayName") -like "Trend Micro Deep Security Agent") -and ($subkey.GetValue("DisplayVersion") -lt '20.0.6313')) {
                Start-Process -FilePath msiexec -ArgumentList "/i C:\Temp\Trend\Agent-Core-Windows.msi /qn ADDLOCAL=ALL /l*v `"$env:LogPath\dsa_install.log`"" -Wait -PassThru
                return $true
            }
            elseif ($subKey.GetValue("DisplayVersion") -eq '20.0.6313') {
                Start-Process -FilePath msiexec -ArgumentList "/fa", "C:\Temp\Trend\Agent-Core-Windows.msi", "/qn" -Wait -PassThru
                return $true
            }
        }
        Start-Process -FilePath msiexec -ArgumentList "/i C:\Temp\Trend\Agent-Core-Windows.msi /qn ADDLOCAL=ALL /l*v `"$env:LogPath\dsa_install.log`"" -Wait -PassThru
        return $true
    }
}


function Test-Connectivity ($session) {
    return Invoke-Command -Session $session -ScriptBlock {
        $endpoints = "app.deepsecurity.trendmicro.com", "agents.workload.gb-1.cloudone.trendmicro.com", "dsmim.deepsecurity.trendmicro.com"
        Set-Location C:\temp\trend

        $results = @()  # Initialize an empty array to hold results
        foreach ($endpoint in $endpoints) {
            $command = ".\tcping.exe -n 1 -w 3 $endpoint 443"
            $output = Invoke-Expression $command  # Execute the command and capture output
            $results += $output  # Append the output to the results array
        }
        return $results  # Return the collected results
    }
}



function Set-Proxy ($session) {
    Invoke-Command -Session $session -ScriptBlock {
    $ipList = @("10.136.3.46", "10.136.3.47", "10.136.3.48")
    $port = 8080
    
    $responseTimes = @{}
    foreach ($ip in $ipList) {
        $output = & '.\tcping.exe' $ip $port
        $responseTime = $output.Split(' ')[-2]
        $responseTimes.Add($ip, $responseTime)
    }
    
    $lowestIp = $responseTimes.GetEnumerator() | Sort-Object Value | Select-Object -First 1
    
    & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -s -0 -p WWIQ7G!fHX$19LQZBZD
    & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -r -p WWIQ7G!fHX$19LQZBZD
    & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -s -0
    & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -r
    & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -x dsm_proxy://$lowestIp.name:8080
    & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -y dsm_proxy://$lowestIp.name:8080
   

}
return $lowestIp.name
}



function Get-RemoteSession {

 

param (   
    [Parameter(Mandatory=$true, ParameterSetName="Server", HelpMessage="PMS Account.")]
    [String] $Server
)

 

    $cred = D:\Thycotic\Get-thycoticCredentials.ps1 -server $server
    $securePassword = ConvertTo-SecureString $cred.password -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential ($cred.username, $securePassword)
    return New-PSSession -ComputerName $server -Credential $psCred
}

 

function Copy-ItemsToRemote ($session) {
    $itemsToCopy = @(
        "D:\Patches\Custom\Trend\NonA1",
        "D:\Patches\Custom\Trend\A1",
        "D:\Patches\Custom\Trend\DSA_CUT",
        "D:\Patches\Custom\Trend\DSASupportTool_GUI",
        "D:\Patches\Custom\Trend\Agent-Core-Windows.msi",
        "D:\Patches\Custom\Trend\endpoint_basecamp_uninstall_tool",
        "D:\Patches\Custom\Trend\tcping.exe"
    )

    $remotePath = "C:\Temp\Trend"

    # Initialize result object
    $resultObj = [PSCustomObject]@{
        IsCopied = $false
        CopiedItems = @()
    }

    # Clear and create remote directory
    Invoke-Command -Session $session -ScriptBlock {
        $directoryPath = "C:\Temp\Trend"
        if (Test-Path $directoryPath) {
            Remove-Item -Path "$directoryPath\*" -Recurse -Force
        }
        New-Item -Path $directoryPath -ItemType Directory -Force
    }

    # Copy items to remote path
    foreach ($item in $itemsToCopy) {
        Copy-Item -Path $item -Destination $remotePath -ToSession $session -Recurse -Force
    }

    # Check if items were copied
    $copyCheck = Invoke-Command -Session $session -ScriptBlock {
        $remotePath = "C:\Temp\Trend"
        $items = Get-ChildItem -Path $remotePath -Recurse
        return $items
    }

    if ($copyCheck.Count -gt 0) {
        $resultObj.IsCopied = $true
        $resultObj.CopiedItems = $copyCheck.FullName
    }

    return $resultObj
}

function Get-TrendServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    
    $properties = @()
    $services = Invoke-Command -Session $Session -ScriptBlock {
        Get-Service | Where-Object { $_.DisplayName -like "Trend*" }
    }

    $output = @()

    if ($services) {
        foreach ($service in $services) {
            $properties = @{
                "Name"        = $service.ServiceName
                "DisplayName" = $service.DisplayName
                "Status"      = $service.Status
            }
            $output += New-Object PSObject -Property $properties
        }
    } else {
        $properties = @{
            "Name"        = "None"
            "DisplayName" = "None"
            "Status"      = "None"
        }
        $output += New-Object PSObject -Property $properties
    }

    if ($?) {
        return $output
    } else {
        $properties = @{
            "Name"        = "ERROR"
            "DisplayName" = "ERROR"
            "Status"      = "ERROR"
        }
        $output = New-Object PSObject -Property $properties
        return $output
    }
}

function Register-Trend {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )

    $scriptBlock = {
        param(
            $computerName,
            $timeout
        )

        $command = "C:\Program Files\Trend Micro\Deep Security Agent\dsa_control.cmd"
        $arrgs = @(
            '-a',
            'dsm://agents.workload.gb-1.cloudone.trendmicro.com:443/',
            'tenantID:BE123086-1CAA-5C3A-2027-3BCB78B797A6',
            'token:9BA0BFE0-65DE-2658-82BB-2AD32ED43100',
            'policyid:562'
        )

        $job = Start-Job -ScriptBlock {
            param($command, $arrgs)
            $process = Start-Process -FilePath $command -ArgumentList $arrgs -RedirectStandardOutput -NoNewWindow -Wait -PassThru
            $process.ExitCode
        } -ArgumentList $command, $arrgs

        $jobFinished = $job | Wait-Job -Timeout $timeout

        if ($jobFinished) {
            $exitCode = Receive-Job -Job $job
            Remove-Job -Job $job
        } else {
            Stop-Job -Job $job
            Remove-Job -Job $job
            return $false
        }

        if ($exitCode -eq 0) {
            return $true
        } else {
            return $false
        }
    }

    $computerName = $Session.ComputerName
    $timeout = 200  # 15 minutes (in seconds)

    $result = Invoke-Command -Session $Session -ScriptBlock $scriptBlock -ArgumentList $computerName, $timeout
    return $result
}


$results = @()

$servers = Get-Content 'C:\input\Servers.txt'
foreach ($server in $servers) {

  $session = Get-RemoteSession -server $server
  
  $copy = Copy-ItemsToRemote -session $session
  $apex = Check-ApexAndRunScut -session $session
  $trend = InstallOrUpdateTrend -session $session
  $connect = Test-Connectivity -session $session
  $service = Get-TrendServices -Session $session
  $proxy = Set-Proxy -session $session
  $trend = Register-Trend -Session $session

  $result = [PSCustomObject]@{
    Server = $server 
    Files = $copy
    ApexInstalled = $apex
    TrendUpdated = $trend
    Connectivity = $connect
    TrendServices = $service
    ProxySet = $proxy
    Trend = $trend
  }

  $results += $result

  Remove-PSSession $session
}

# Output table
$results | Format-Table

# Output CSV
$results | Export-Csv -Path 'C:\output\results.csv' -NoTypeInformation