$servers = get-content C:\temp\servers.txt
$Results = $null
$Results = @()


function set-credential {
    param (
        $computername
    )

    $FQDN = [net.dns]::GetHostEntry($computername).Hostname
    $FQDNfinal = $FQDN.Split( "." )[1]
    switch -Wildcard ($FQDNfinal) {
        "corp" {
            $AccountName = "corp.ad.tullib.com\CORP PMS"
            $accontPassword = ConvertTo-SecureString -String '4i$PnNi360@hk!YiRLzoFjBUs$4cbX6D' -AsPlainText -Force
        }
        "ad" {
            $AccountName = "AD.tullib.com\RT TPICAP PMS"
            $accontPassword = ConvertTo-SecureString -String "eOB9DcPig6tevcZU5xRCa8w)Lw^#fVm9" -AsPlainText -Force
        }
        "apac" {
            $AccountName = "apac.ad.tullib.com\APAC PMS"
            $accontPassword = ConvertTo-SecureString -String "$B4s8KQ2T9&b(N^DD*g1&PMWvh6H*3)S" -AsPlainText -Force
        }
        "eur" {
            $AccountName = "EUR\EUR PMS"
            $accontPassword = ConvertTo-SecureString -String "muGGO7zX!#l#(O0!B91YPAL%FotoB13e" -AsPlainText -Force
        }
        "na" {
            $AccountName = "NA\NA PMS"
            $accontPassword = ConvertTo-SecureString -String "WLetCv#xSfHm%7So$fG6Q^ez3xMfs66W" -AsPlainText -Force
        }
        "au" {
            $AccountName = "au.icap.com\AU PMS"
            $accontPassword = ConvertTo-SecureString -String "QgipEtXuEE3Wwn2qr8k%^Va61G1(lVw6" -AsPlainText -Force
        }
        "br" {
            $AccountName = "br.icap.com\BR PMS"
            $accontPassword = ConvertTo-SecureString -String "i@Dx8!^6#H4@^bA" -AsPlainText -Force
        }
        "global" {
            $AccountName = "GLOBAL\GLOBAL PMS"
            $accontPassword = ConvertTo-SecureString -String "fUqy@QW%kuoMoaVuZA^&EK2!7w#XU0k*" -AsPlainText -Force
        }
        "hk" {
            $AccountName = "HK\HK PMS"
            $accontPassword = ConvertTo-SecureString -String "FDihg2*9hO3iwjGYB1azCUSUqfjm0olq" -AsPlainText -Force
        }
        "jpn" {
            $AccountName = "JPN\JPN PMS"
            $accontPassword = ConvertTo-SecureString -String "4xjqT9Lq!zkkmzcwlvR^yv@PYqOCAw#a" -AsPlainText -Force
        }
        "uk" {
            $AccountName = "UK\UK PMS"
            $accontPassword = ConvertTo-SecureString -String "*ZJpfi8gQ4l*gL1VOgh8z7d**9#^Ns02" -AsPlainText -Force
        }
        "us" {
            $AccountName = "US\US PMS"
            $accontPassword = ConvertTo-SecureString -String "jfL2M09a*mlvu8h%%OgMROfl4nlnwBT!" -AsPlainText -Force
        }
        "lnholdings" {
            $AccountName = "lnholdings.com\LN PMS"
            $accontPassword = ConvertTo-SecureString -String "D3k!6AkOwyxZOUSo" -AsPlainText -Force
        }
        "icap" {
            $AccountName = "icap.com\RT ICAP PMS"
            $accontPassword = ConvertTo-SecureString -String "n(7WN0oV@vp&Q4@XjUn" -AsPlainText -Force
        }
        "ebdev" {
            $AccountName = 'ebdev.tpebroking.com\EBDEV PMS'
            $accontPassword = ConvertTo-SecureString -String "PyuRxEpY7ZrGl9fY8z6z7OA#H2j7geu^" -AsPlainText -Force
        }
        "sg" {
            $AccountName = 'sg.icap.com\SG PMS'
            $accontPassword = ConvertTo-SecureString -String 'dIs@)^xNXQGuZV(j65Xugby!U&R*Mmio' -AsPlainText -Force
        }
        "pvm" {
            $AccountName = 'pvm.co.uk\PVM PMS'
            $accontPassword = ConvertTo-SecureString -String 'n(7WN0oV@vp&Q4@XjUn' -AsPlainText -Force
        }
        
    }
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AccountName, $accontPassword

    return $creds
}

function Get-serverOS {
    param (
        [Parameter(Mandatory = $true)]
        [string]$computerName,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$credential
    )
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computerName -Credential $credential | Select-Object -ExpandProperty Caption
        return $os
    }
    catch {
        return 'Error'
    }     
}

function Test-RemotePort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$remoteComputer,
        
                
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$credentials
    )
    
    # Set paths for local and remote tcping.exe
    $remoteTcpingPath = "C:\temp\tcping.exe"
    
    
    # Check if tcping.exe exists on remote computer, and copy if necessary
    $session = New-PSSession -ComputerName $remoteComputer -Credential $credentials
    $tcpingExists = Invoke-Command -Session $session -ScriptBlock { param($remoteTcpingPath)
        Test-Path $remoteTcpingPath } -ArgumentList $remoteTcpingPath


    if ($tcpingExists -eq $false) {
    
    write-host "transferring files to $remoteComputer"
    
    copy-item -path "C:\share\tcping.exe" -destination "C:\temp\" -recurse -toSession $Session
    
    
    }elseif ($tcpingExists -eq $true){
    
    Write-Host "file exist"

    }else{
    
    Write-host "Error"
    
    }
    
    
    
    
    
    $output = Invoke-Command -Session $session -ScriptBlock {      
      Set-Location C:\temp
      & .\tcping.exe -n 1 -w 2 app.deepsecurity.trendmicro.com 443
       
      
    } 
    Remove-PSSession $session
    
    
    return $output
}

function Get-RemoteComputerInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$RemoteComputerName,
        [Parameter(Mandatory=$true)]
        [pscredential]$Credential
    )

    $websites = "app.deepsecurity.trendmicro.com", "agents.workload.gb-1.cloudone.trendmicro.com", "dsmim.deepsecurity.trendmicro.com"

    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -IncludePortInSPN
    $session = New-PSSession -ComputerName $remoteComputerName -SessionOption $sessionOption -Credential $Credential

    try {
        Invoke-Command -Session $session -ScriptBlock {
            param($websites)

            Set-ExecutionPolicy -ExecutionPolicy "Unrestricted" -Scope LocalMachine -Force

            $results = New-Object -TypeName PSObject -Property @{
                OS = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
                IPAddress = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }).IPAddress
                Services = Get-Service -Name "Trend*" | Select-Object -Property Name, Status
                InstalledApps = [ordered]@{}
                TcppingResult = @{}
            }

            $uninstallKeys = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )

            foreach ($key in $uninstallKeys) {
                $apps = Get-ItemProperty $key |
                    Where-Object { $_.Publisher -like "*Trend*" } |
                    Select-Object -Property DisplayName, DisplayVersion, Publisher

                foreach ($app in $apps) {
                    if (-not $results.InstalledApps.ContainsKey($app.DisplayName)) {
                        $results.InstalledApps[$app.DisplayName] = $app
                    }
                }
            }

            $results.InstalledApps = $results.InstalledApps.Values | Sort-Object -Property DisplayName

            $tcppingPath = "C:\temp\Tcpping.exe"

            if (-not (Test-Path $tcppingPath)) {
                $tcpingSourcePath = "\\10.90.80.243\Share\Tcpping.exe" # Replace with the local path of the tcping.exe file
                $tcpingDestinationPath = "C:\temp\Tcpping.exe"
                Copy-Item -Path $tcpingSourcePath -Destination $tcpingDestinationPath
            }

            foreach ($website in $websites) {
                $result = & $tcppingPath $website 80 -t 1 -w 2
                if ($result -match "Reply from") {
                    $results.TcppingResult[$website] = "Open"
                } else {
                    $results.TcppingResult[$website] = "Closed"
                }
            }

            $results
        } -ArgumentList $websites
    }
    catch {
        Write-Error $_.Exception.Message
    }
    finally {
        Remove-PSSession -Session $session
    }
}


foreach ($server in $servers) {

    if(Test-Connection $server -count 2)
    {
        $credential = set-credential -computerName $server
        $result = Get-RemoteComputerInfo -RemoteComputerName $server -Credential $credential
        $result
        
    }

    else {
        write-host Error
 
    }
    
    
}
#$Result | Format-list
#$Results | Convert-OutputForCSV | Export-Csv C:\temp\trendscan.csv