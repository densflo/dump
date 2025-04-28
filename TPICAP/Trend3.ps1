$servers = get-content C:\temp\servers.txt
$Results = $null
$Results = @()
$Service = @()
$Appname = @()
. 'C:\Users\dflores-a\Documents\Convert-OutputForCSV.ps1'


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
    if ($FQDNfinal -eq $null) {
        $AccountName = 'nv'
    }
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AccountName, $accontPassword

    return $creds
}

function Enable-PSRemoting {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    $LocalFilePath = "C:\temp\PSremote.cmd"
    $RemoteFilePath = "\\$ComputerName\c$\temp\PSremote.cmd"
    $PsexecPath = "C:\Temp\PsExec.exe"
    & $PsexecPath \\$ComputerName -u Domain\Username -p Password -c -f $LocalFilePath $RemoteFilePath '/accepteula'
    Write-Host "Testing WSMan connectivity to $ComputerName"
    $wsman = Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue
    if ($null -eq $wsman) {
        Write-Host "WSMan test failed for $ComputerName. Enabling WSMan and PowerShell remoting using PsExec."
        $securepass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password))
    
        $psremoting = & $PsexecPath \\$ComputerName -u $Credential.UserName -p $securepass -c -f $LocalFilePath $RemoteFilePath '/accepteula'

        
        & $PsexecPath \\$ComputerName -u $Credential.UserName -p $securepass $RemoteFilePath '/accepteula'

        
        $wsman = Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue
        if ($null -eq $psremoting) {
            Write-Host "WSMan test failed for $ComputerName even after enabling WSMan and PowerShell remoting using PsExec. Exiting."
            continue
        }
    }
    Start-Sleep 5
    Write-Host "Testing WSMan connectivity to $ComputerName"
    $wsman = Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue
    if ($null -eq $wsman) {
        Write-Host "PS Remoting on $ComputerName failed"
    }
    Else {
        Write-Host "PowerShell remoting is enabled on $ComputerName"
    }
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
    
    
    $remoteTcpingPath = "C:\temp\tcping.exe"
    
    
    
    $session = New-PSSession -ComputerName $remoteComputer -Credential $credentials
    $tcpingExists = Invoke-Command -Session $session -ScriptBlock { param($remoteTcpingPath)
        Test-Path $remoteTcpingPath } -ArgumentList $remoteTcpingPath


    if ($tcpingExists -eq $false) {
    
        write-host "transferring files to $remoteComputer"
    
        copy-item -path "C:\Temp\tcping.exe" -destination "C:\temp\" -recurse -toSession $Session
    
    
    }
    elseif ($tcpingExists -eq $true) {
    
        Write-Host "file exist"

    }
    else {
    
        Write-host "Error"
    
    }
    $output = Invoke-Command -Session $session -ScriptBlock {      
        $endpoints = "app.deepsecurity.trendmicro.com", "agents.workload.gb-1.cloudone.trendmicro.com", "dsmim.deepsecurity.trendmicro.com"
        Set-Location C:\temp
        foreach ($endpoint in $endpoints) {
            $TCPoutput = (& ".\tcping.exe" -n 1 -w 2 $endpoint 443)
            $response = $TCPoutput[1]
            if ($TCPoutput -like "DNS=*") {
                Write-Output "DNS FAILED"
                continue
            }
            Write-Output $response
        }
    }


    Remove-PSSession $session
    
    
    return $output
}

function Get-ApplicationsBySearchString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$RemoteComputerName,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory)]
        [string]$SearchString
    )
    
    $session = $null
    $applications = [pscustomobject]@{
        DisplayName = $null
        Version     = $null
        InstallDate = $null
        Error       = $null
    }

    try {
        $session = New-PSSession -ComputerName $RemoteComputerName -Credential $Credentials -ErrorAction Stop
    
        $scriptBlock = {
            param (
                [Parameter(Mandatory)]
                [string]$SearchString
            )
            
            # Get the uninstall registry key hive
            $uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"

            # Get the uninstall registry key wow6432 node
            $uninstallWow6432Node = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

            # Get all the subkeys in the uninstall registry key hive

            

            $subKeys = Get-ChildItem -Path $uninstallKey 

            # Get all the subkeys in the uninstall registry key wow6432 node
            $subKeysWow6432Node = Get-ChildItem -Path $uninstallWow6432Node 

            # Combine the subkeys from both the hive and wow6432 node
            $subKeys += $subKeysWow6432Node

            $applications = @()
            # Loop through all the subkeys and check if the DisplayName value contains the search string
            foreach ($subKey in $subKeys) {
                $displayName = $subKey.GetValue("DisplayName")
                if ($displayName -match $SearchString) {
                    $version = $subKey.GetValue("DisplayVersion")
                    $installDate = $subKey.GetValue("InstallDate")
                    $application = [pscustomobject]@{
                        DisplayName = $displayName
                        Version     = $version
                        InstallDate = $installDate
                    }
                    $applications += $application
                }
            }

            if ($applications) {
                return $applications
            }
            else {
                $applications = [pscustomobject]@{
                    DisplayName = 'None'
                    Version     = 'None'
                    InstallDate = 'None'
                    Error       = 'None'
                }
            }
        }

        $applications = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $SearchString
    
    }
    catch {
        $applications = [pscustomobject]@{
            DisplayName = 'Error'
            Version     = 'Error'
            InstallDate = 'Error'
            Error       = 'Error'
        }
    }
    finally {
        if ($session) {
            Remove-PSSession -Session $session
        }
    }

    return $applications
}

function Get-TrendServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteComputer,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credentials
    )
    
    $properties = @()
    $services = Invoke-Command -ComputerName $RemoteComputer -Credential $Credentials -ScriptBlock {
        Get-Service -DisplayName "Trend*"
    }

    if ($services) {
        $output = @()
        foreach ($service in $services) {
            $properties = @{
                "Name"        = $service.Name
                "DisplayName" = $service.DisplayName
                "Status"      = $service.Status
            }
            $output += New-Object PSObject -Property $properties
        }
    }
    else {
        $properties = @{
            "Name"        = "None"
            "DisplayName" = "None"
            "Status"      = "None"
        }
        $output += New-Object PSObject -Property $properties
    }

    if ($?) {
        return $output
    }
    else {
        $properties = @{
            "Name"        = "ERROR"
            "DisplayName" = "ERROR"
            "Status"      = "ERROR"
        }
        $output = New-Object PSObject -Property $properties
        return $output
    }
}


foreach ($server in $servers) {
    $FQDN = [net.dns]::GetHostEntry($computername).Hostname
    $FQDNfinal = $FQDN.Split( "." )[1]
    if ($FQDNfinal -eq $null) {
        
    }
    $creds = set-credential -computername $server
    $FQDN = [net.dns]::GetHostEntry($server).Hostname
    $Connection = Test-Connection $server -count 2
    if ($Connection) {
        $Status = $true
        $IP = $connection.ipv4address[1].IPAddressToString
        Enable-PSRemoting -ComputerName $server -Credential $creds
        $osversion = Get-serverOS -computerName $server -credential $creds
        $dns1 = Test-RemotePort -remoteComputer $server -credentials $creds

        $Appname = Get-ApplicationsBySearchString -RemoteComputerName $server -Credentials $creds -SearchString 'Trend'
        $Service = Get-TrendServices -RemoteComputer $server -Credentials $creds
    }
    else {
        $Status = 'False'
        $IP = 'None'
        $osversion = 'Error'
        $Appname.DisplayName = 'Not Reachable'
        $Appname.Version = 'Not Reachable'
        $Service.DisplayName = 'Not Reachable'
        $service.Status = 'Not Reachable'
        $dns1 = 'Error'
        
 
    }
    $Obj = New-Object -TypeName PSOBject
    $Obj | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $server
    $Obj | Add-Member -MemberType NoteProperty -Name "Domain" -Value $FQDNfinal
    $Obj | Add-Member -MemberType NoteProperty -Name "OS Version" -Value $osversion
    $Obj | Add-Member -MemberType NoteProperty -Name "Ping"  -Value $Status
    $Obj | Add-Member -MemberType NoteProperty -Name "IP"  -Value $IP
    $Obj | Add-Member -MemberType NoteProperty -Name "APP Name"  -Value $Appname.DisplayName
    $Obj | Add-Member -MemberType NoteProperty -Name "Version"  -Value $Appname.Version
    $Obj | Add-Member -MemberType NoteProperty -Name "Possible Service"  -Value $Service.DisplayName
    $Obj | Add-Member -MemberType NoteProperty -Name "Status"  -Value $service.Status
    $Obj | Add-Member -MemberType NoteProperty -Name "Port Check"  -Value $dns1
     
    $Results += $Obj
    $dns1 = $null
    
}
$Results | Format-Table -autosize -wrap
$Results | Convert-OutputForCSV | Export-Csv C:\temp\trendscan.csv