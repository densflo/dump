$servers = get-content C:\temp\servers.txt
$Results = $null
$Results = @()
$port = 443
$endpoint1 = 'app.deepsecurity.trendmicro.com'
$endpoint2 = 'agents.workload.gb-1.cloudone.trendmicro.com'
$endpoint3 = 'dsmim.deepsecurity.trendmicro.com'

function set-credential {
    param (
        $computername
    )

    $FQDN = [net.dns]::GetHostEntry($computername).Hostname
    $FQDNfinal = $FQDN.Split( "." )[1]
    switch -Wildcard ($FQDNfinal) {
        "corp" {
            $AccountName = "corp.ad.tullib.com\CORP PMS"
            $accontPassword = ConvertTo-SecureString -String "cO0Ja^&XGzIRjdNQq7IYC*VYm(5IJ&RM" -AsPlainText -Force
        }
        "ad" {
            $AccountName = "AD.tullib.com\RT TPICAP PMS"
            $accontPassword = ConvertTo-SecureString -String "Xoe1A$XSpjIhEEKo1HX@S%Tm!bNNKiGN" -AsPlainText -Force
        }
        "apac" {
            $AccountName = "apac.ad.tullib.com\APAC PMS"
            $accontPassword = ConvertTo-SecureString -String "FwA48Ubmz@jDm3YzY7ZCLTf7)*J!#RrG" -AsPlainText -Force
        }
        "eur" {
            $AccountName = "EUR\EUR PMS"
            $accontPassword = ConvertTo-SecureString -String "2MWRnnoobQtUJ98VUh5EoYC7Qnm$J(H@" -AsPlainText -Force
        }
        "na" {
            $AccountName = "NA\NA PMS"
            $accontPassword = ConvertTo-SecureString -String "HI))QL^NbOjnd(Uz9Tk09@MMjbi@gIK%" -AsPlainText -Force
        }
        "au" {
            $AccountName = "au.icap.com\AU PMS"
            $accontPassword = ConvertTo-SecureString -String "Nx^L%8WP15Q(UJ(zIuRNY1QvsBI1)Kkz" -AsPlainText -Force
        }
        "br" {
            $AccountName = "br.icap.com\BR PMS"
            $accontPassword = ConvertTo-SecureString -String "G5jiZE(jv@AWhto" -AsPlainText -Force
        }
        "global" {
            $AccountName = "GLOBAL\GLOBAL PMS"
            $accontPassword = ConvertTo-SecureString -String "ry&Sw5p@P1ZY6sLFQxyK88ieQ#otXM(r" -AsPlainText -Force
        }
        "hk" {
            $AccountName = "HK\HK PMS"
            $accontPassword = ConvertTo-SecureString -String "$Nb%8kQ!UwEVN6rqy8CcxxrSNPGvocGH" -AsPlainText -Force
        }
        "jpn" {
            $AccountName = "JPN\JPN PMS"
            $accontPassword = ConvertTo-SecureString -String "vc2w6imvzCG*49d8e5Af7!^0mUubnAbW" -AsPlainText -Force
        }
        "uk" {
            $AccountName = "UK\UK PMS"
            $accontPassword = ConvertTo-SecureString -String "qc)52!AdzydT5sgBwo*nE9RP%gPIPHIA" -AsPlainText -Force
        }
        "us" {
            $AccountName = "US\US PMS"
            $accontPassword = ConvertTo-SecureString -String "JGkiIzX4uFzuR*wXosbO*U16NV^5JO6B" -AsPlainText -Force
        }
        "lnholdings" {
            $AccountName = "lnholdings.com\LN PMS"
            $accontPassword = ConvertTo-SecureString -String "v@m2c@qlh54zZfx%s%" -AsPlainText -Force
        }
        "icap" {
            $AccountName = "icap.com\RT ICAP PMS"
            $accontPassword = ConvertTo-SecureString -String "UDcB%rie@lqHGXM)0sk)^Hv48m*O)zN9" -AsPlainText -Force
        }
        "ebdev" {
            $AccountName = 'ebdev.tpebroking.com\EBDEV PMS'
            $accontPassword = ConvertTo-SecureString -String "ekcz0EItIqU0(uzLcUEn^h6a%5PkZ^cL" -AsPlainText -Force
        }
        "sg" {
            $AccountName = 'sg.icap.com\SG PMS'
            $accontPassword = ConvertTo-SecureString -String ')GGn#m@bP4$(RMk0KxXN%OPAfXBESyFt' -AsPlainText -Force
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
        [Parameter(Mandatory=$true)]
        [string]$remoteComputer,
        
        [Parameter(Mandatory=$true)]
        [int]$remotePort,
        
        [Parameter(Mandatory=$true)]
        [string]$remoteEndpoint,
        
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$credentials
    )
    
    # Set paths for local and remote tcping.exe
    $localTcpingPath = "\\10.90.80.243\Share\tcping.exe"
    $remoteTcpingPath = "C:\temp\tcping.exe"
    
    # Check if tcping.exe exists on remote computer, and copy if necessary
    $session = New-PSSession -ComputerName $remoteComputer -Credential $credentials
    $tcpingExists = Invoke-Command -Session $session -ScriptBlock { 
    Copy-Item -Path $localTcpingPath -Destination "C:\temp\"
    Test-Path "$using:remoteTcpingPath"
    
     }
    if (-not $tcpingExists) {
        Write-Verbose "Copying tcping.exe to $remoteComputer..."
        Copy-Item -Path "\\10.90.80.243\Share\tcping.exe" -destination "C:\Temp\"
    }
    Remove-PSSession $session
    
    # Test the remote connection using tcping.exe
    $session = New-PSSession -ComputerName $remoteComputer -Credential $credentials
    $output = Invoke-Command -Session $session -ScriptBlock {
        & "$using:remoteTcpingPath" $using:remoteEndpoint $using:remotePort -t -n 1 |
        Select-String -Pattern "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -AllMatches |
        ForEach-Object { $_.Matches.Value }
    }
    Remove-PSSession $session
    
    # Check the output for success or failure
    if ($output) {
        $ip = $output
        $status = "Open"
    } else {
        $ip = "Not resolvable"
        $status = "Close"
    }
    
    # Return the result as a string
    return "{0} on port {1} is {2}." -f $ip, $remotePort, $status
}


foreach ($server in $servers) {

    $creds = set-credential -computername $server
    $FQDN = [net.dns]::GetHostEntry($server).Hostname
    $FQDNfinal = $FQDN.Split( "." )[1]
    $Connection = Test-Connection $server -count 2
    if ($Connection) {
        $Status = $true
        $IP = $connection.ipv4address[1].IPAddressToString
        $osversion = Get-serverOS -computerName $server -credential $creds
        $dns1 = Test-RemotePort -remoteComputer $server -remoteEndpoint $endpoint1 -remotePort $port -credentials $creds
        $dns1 = Test-RemotePort -remoteComputer $server -remoteEndpoint $endpoint2 -remotePort $port -credentials $creds
        $dns1 = Test-RemotePort -remoteComputer $server -remoteEndpoint $endpoint3 -remotePort $port -credentials $creds

        Try {
            $app = Get-WmiObject -Class Win32_Product -ComputerName $server -Credential $Creds | Where-Object vendor -eq "Trend Micro Inc." -ErrorAction Continue
            if ($app.Name) {
                $Appname = $app.Name
                $Appversion = $app.Version
            }
            Else {
                $Appname = 'None'
                $Appversion = 'None'
            }
        }
        Catch {
            $Appname = 'Error'
            $Appversion = 'Error'
        }
        Try {
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $server -Credential $creds | Where-Object { $_.DisplayName -like "Trend*" }
            if ($Service) {
                $ServiceName = $Service.Displayname
                $ServiceStatus = $Service.Status
            }
            Else {
                $ServiceName = 'None'
                $ServiceStatus = 'None'
            }
        }
        Catch {
            $ServiceName = 'Error'
            $ServiceStatus = 'Error'
        }
    }
    else {
        $Status = 'False'
        $IP = 'None'
        $osversion = 'Error'
        $Appname = 'Not Reachable'
        $Appversion = 'Not Reachable'
        $ServiceName = 'Not Reachable'
        $ServiceStatus = 'Not Reachable'
        $dns1 = 'Error'
        $dns2 = 'Error'
        $dns3 = 'Error'
 
    }
    $Obj = New-Object -TypeName PSOBject
    $Obj | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $server
    $Obj | Add-Member -MemberType NoteProperty -Name "Domain" -Value $FQDNfinal
    $Obj | Add-Member -MemberType NoteProperty -Name "OS Version" -Value $osversion
    $Obj | Add-Member -MemberType NoteProperty -Name "Ping"  -Value $Status
    $Obj | Add-Member -MemberType NoteProperty -Name "IP"  -Value $IP
    $Obj | Add-Member -MemberType NoteProperty -Name "APP Name"  -Value $Appname
    $Obj | Add-Member -MemberType NoteProperty -Name "Version"  -Value $Appversion
    $Obj | Add-Member -MemberType NoteProperty -Name "Possible Service"  -Value $ServiceName
    $Obj | Add-Member -MemberType NoteProperty -Name "Status"  -Value $ServiceStatus
    $Obj | Add-Member -MemberType NoteProperty -Name "app.deepsecurity.trendmicro.com"  -Value $dns1
    $Obj | Add-Member -MemberType NoteProperty -Name "agents.workload.gb-1.cloudone.trendmicro.com"  -Value $dns2
    $Obj | Add-Member -MemberType NoteProperty -Name "dsmim.deepsecurity.trendmicro.com"  -Value $dns3
   
    $Results += $Obj
    $dns1 = $null
    $dns2 = $null
    $dns3 = $null
}
$Results | Format-Table -autosize -wrap
$Results | Convert-OutputForCSV | Export-Csv C:\temp\trendscan.csv