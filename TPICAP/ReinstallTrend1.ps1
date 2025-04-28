function Uninstall-TrendMicro {
    param (
        [string]$ComputerName,
        [PSCredential]$Credentials
    )

    $uninstallComplete  = $false
    $uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstallWow6432Node = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

    $apexOne = Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock {
        Get-ItemProperty -Path $using:uninstallKey, $using:uninstallWow6432Node | Where-Object { $_.DisplayName -like "Apex One*" }
    }
    $deepSecurity = Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock {
        Get-ItemProperty -Path $using:uninstallKey, $using:uninstallWow6432Node | Where-Object { $_.DisplayName -like "*Deep Security*" }
    }
    $officeScan = Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock {
        Get-ItemProperty -Path $using:uninstallKey, $using:uninstallWow6432Node | Where-Object { $_.DisplayName -like "*OfficeScan*" }
    }

    if ($apexOne) {
        Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock {
            Start-Process -FilePath "C:\temp\trend\A1\scut.exe" -ArgumentList "-noinstall" "-dbg" -Wait

        }
    }
    elseif ($deepSecurity) {
        Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock {
            Start-Process -FilePath "C:\temp\trend\DSA_CUT\DSA_cut.exe" -Wait
        }
    }
    elseif ($officeScan) {
        Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock {
            Start-Process -FilePath "C:\temp\trend\NonA1\scut.exe" -ArgumentList "-noinstall" "-dbg" -Wait

        }
    }
    else {
        $uninstallComplete = $true
    }
    

    # Test if Trend Micro products are uninstalled
    $isTrendMicroUninstalled = Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock {
        $using:uninstallKey, $using:uninstallWow6432Node | Get-ItemProperty | Where-Object { $_.DisplayName -like "*Trend Micro*" } | Measure-Object | Select-Object -ExpandProperty Count -eq 0
    }

    return $isTrendMicroUninstalled
}

function set-credential {
    param (
        $computername
    )

    $FQDN = [net.dns]::GetHostEntry($computername).Hostname
    $FQDNfinal = $FQDN.Split( "." )[1]
    switch -Wildcard ($FQDNfinal) {
        "corp" {
            $AccountName = "corp.ad.tullib.com\CORP PMS"
            $accontPassword = ConvertTo-SecureString -String 'D*Iz5m(8*MRGUgFs%(4xoMyN@ihoUUYa' -AsPlainText -Force
        }
        "ad" {
            $AccountName = "AD.tullib.com\RT TPICAP PMS"
            $accontPassword = ConvertTo-SecureString -String 'KAA3Y2m(KbCNr^TPj^4!hpmKW#jiW3T@' -AsPlainText -Force
        }
        "apac" {
            $AccountName = "apac.ad.tullib.com\APAC PMS"
            $accontPassword = ConvertTo-SecureString -String 'yfw533mnYt6PZ3$XPFQMZ89n(kwq@g#x' -AsPlainText -Force
        }
        "eur" {
            $AccountName = "EUR\EUR PMS"
            $accontPassword = ConvertTo-SecureString -String 'vTzqrb3A9k2QpQQ2VeyA69#dOJtmJjDp' -AsPlainText -Force
        }
        "na" {
            $AccountName = "NA\NA PMS"
            $accontPassword = ConvertTo-SecureString -String 'ehG7BMdU7lY@9x&5Iz#C*Ky@RS$)v@zu' -AsPlainText -Force
        }
        "au" {
            $AccountName = "au.icap.com\AU PMS"
            $accontPassword = ConvertTo-SecureString -String '39#r703&WG5S&45gjDsbTZB33KQ3ksjW' -AsPlainText -Force
        }
        "br" {
            $AccountName = "br.icap.com\BR PMS"
            $accontPassword = ConvertTo-SecureString -String 'Jz3CuxnbBRcXWU' -AsPlainText -Force
        }
        "global" {
            $AccountName = "GLOBAL\GLOBAL PMS"
            $accontPassword = ConvertTo-SecureString -String 'wP9@J2emcuK*ZkHrlJy&c*wRgMczw9!w' -AsPlainText -Force
        }
        "hk" {
            $AccountName = "HK\HK PMS"
            $accontPassword = ConvertTo-SecureString -String 'kL!X^*Cf2f9xP$xFfKMaahzCe%!Ivbi1' -AsPlainText -Force
        }
        "jpn" {
            $AccountName = "JPN\JPN PMS"
            $accontPassword = ConvertTo-SecureString -String '#VVw8bmN*McsSkBu*O0O8JT7PCb(rmo!' -AsPlainText -Force
        }
        "uk" {
            $AccountName = "UK\UK PMS"
            $accontPassword = ConvertTo-SecureString -String 'le7(YKA^d$7mzaD3dpVX2d@4h2@XQkxZ' -AsPlainText -Force
        }
        "us" {
            $AccountName = "US\US PMS"
            $accontPassword = ConvertTo-SecureString -String 'zu*8ARlgN8smReA5CTDR7d7I4TaB@I)$' -AsPlainText -Force
        }
        "lnholdings" {
            $AccountName = "lnholdings.com\LN PMS"
            $accontPassword = ConvertTo-SecureString -String 'B!6rZr(#OclJ7z%' -AsPlainText -Force
        }
        "icap" {
            $AccountName = "icap.com\RT ICAP PMS"
            $accontPassword = ConvertTo-SecureString -String 'JXmHSfb2%cuVXTI^f!u(eMf%7EX&nZBN' -AsPlainText -Force
        }
        "ebdev" {
            $AccountName = 'ebdev.tpebroking.com\EBDEV PMS'
            $accontPassword = ConvertTo-SecureString -String 'A6AMULu#Rw)r&p6)KNufA)OJ6nY^a4L!' -AsPlainText -Force
        }
        "sg" {
            $AccountName = 'sg.icap.com\SG PMS'
            $accontPassword = ConvertTo-SecureString -String '47IIk(t2)3lbR9ZCWzQd9Lpxbls)$Um6' -AsPlainText -Force
        }
        "pvm" {
            $AccountName = 'pvm.co.uk\PVM PMS'
            $accontPassword = ConvertTo-SecureString -String 'n(7WN0oV@vp&Q4@XjUn' -AsPlainText -Force
        }
        
    }
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AccountName, $accontPassword

    return $creds
} 

function Install-DeepSecurityAgent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RemoteComputerName,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credentials
    )

    $Result = @{
        Status = $false
        Output = ""
    }

    $managerUrl = "https://workload.gb-1.cloudone.trendmicro.com:443/"
    $ACTIVATIONURL = "dsm://agents.workload.gb-1.cloudone.trendmicro.com:443/"

    $ScriptBlock = {
        param (
            $managerUrl,
            $ACTIVATIONURL,
            $Credentials
        )

        #requires -version 4.0



        # PowerShell 4 or up is required to run this script

        # This script detects platform and architecture.  It then downloads and installs the relevant Deep Security Agent package



        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

            Write-Warning "You are not running as an Administrator. Please try again with admin privileges."

            exit 1

        }



        $managerUrl = "https://workload.gb-1.cloudone.trendmicro.com:443/"



        $env:LogPath = "$env:appdata\Trend Micro\Deep Security Agent\installer"

        New-Item -path $env:LogPath -type directory

        Start-Transcript -path "$env:LogPath\dsa_deploy.log" -append



        write-output "$(Get-Date -format T) - DSA download started"

        if ( [intptr]::Size -eq 8 ) { 

            $sourceUrl = -join ($managerUrl, "software/agent/Windows/x86_64/agent.msi") 
        }

        else {

            $sourceUrl = -join ($managerUrl, "software/agent/Windows/i386/agent.msi") 
        }

        write-output "$(Get-Date -format T) - Download Deep Security Agent Package" $sourceUrl



        $ACTIVATIONURL = "dsm://agents.workload.gb-1.cloudone.trendmicro.com:443/"



        $WebClient = New-Object System.Net.WebClient



        # Add agent version control info

        $WebClient.Headers.Add("Agent-Version-Control", "on")

        $WebClient.QueryString.Add("tenantID", "50202")

        $WebClient.QueryString.Add("windowsVersion", (Get-CimInstance Win32_OperatingSystem).Version)

        $WebClient.QueryString.Add("windowsProductType", (Get-CimInstance Win32_OperatingSystem).ProductType)



        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;



        Try {

            $WebClient.DownloadFile($sourceUrl, "$env:temp\agent.msi")

        }
        Catch [System.Net.WebException] {

            write-output " Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority."

            exit 2;

        }



        if ( (Get-Item "$env:temp\agent.msi").length -eq 0 ) {

            write-output "Failed to download the Deep Security Agent. Please check if the package is imported into the Workload Security Manager. "

            exit 1

        }

        write-output "$(Get-Date -format T) - Downloaded File Size:" (Get-Item "$env:temp\agent.msi").length



        write-output "$(Get-Date -format T) - DSA install started"

        write-output "$(Get-Date -format T) - Installer Exit Code:" (Start-Process -FilePath msiexec -ArgumentList "/i $env:temp\agent.msi /qn ADDLOCAL=ALL /l*v `"$env:LogPath\dsa_install.log`"" -Wait -PassThru).ExitCode 

        write-output "$(Get-Date -format T) - DSA activation started"



        Start-Sleep -s 50

        & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -r

        & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -a $ACTIVATIONURL "tenantID:BE123086-1CAA-5C3A-2027-3BCB78B797A6" "token:9BA0BFE0-65DE-2658-82BB-2AD32ED43100" "policyid:562"

        #& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -a dsm://agents.workload.gb-1.cloudone.trendmicro.com:443/ "tenantID:BE123086-1CAA-5C3A-2027-3BCB78B797A6" "token:9BA0BFE0-65DE-2658-82BB-2AD32ED43100" "policyid:562"

        Stop-Transcript

        Write-Output "$(Get-Date -format T) - DSA Deployment Finished"

        @{
            Status = $true
            Output = "The output of dsa_control.cmd"
        }
    }
    $Result = Invoke-Command -ComputerName $RemoteComputerName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $managerUrl, $ACTIVATIONURL, $Credential

    return $Result
}


function Copy-TrendFolder {
    param (
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][pscredential]$Credential,
        [string]$LocalPath = "C:\temp\Trend",
        [string]$RemotePath = "C:\temp\Trend"
    )

    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential

    try {
        # Prepare the remote temp folder
        Invoke-Command -Session $session -ScriptBlock {
            $tempFolderPath = "C:\temp"
            $trendFolderPath = "C:\temp\trend"

            if (-not (Test-Path $tempFolderPath)) {
                New-Item -ItemType Directory -Path $tempFolderPath | Out-Null
            }

            if (Test-Path $trendFolderPath) {
                Remove-Item -Path $trendFolderPath -Recurse -Force
            }
        }

        # Get the content from the source and destination folders
        $sourceFiles = Get-ChildItem -Path $LocalPath -Recurse | Resolve-Path -Relative
        $destinationFiles = Invoke-Command -Session $session -ScriptBlock {
            param($RemotePath)

            if (Test-Path $RemotePath) {
                Get-ChildItem -Path $RemotePath -Recurse | Resolve-Path -Relative
            }
            else {
                return @()
            }
        } -ArgumentList $RemotePath

        # Filter the files that are missing in the destination folder
        $filesToCopy = Compare-Object -ReferenceObject $sourceFiles -DifferenceObject $destinationFiles -PassThru

        # Copy the missing files from local machine to remote machine
        if ($filesToCopy.Count -gt 0) {
            Write-Host "Copying $($filesToCopy.Count) files to $ComputerName"
            foreach ($file in $filesToCopy) {
                $sourceFile = Join-Path -Path $LocalPath -ChildPath $file
                $destinationFile = Join-Path -Path $RemotePath -ChildPath $file
                Copy-Item -Path $sourceFile -Destination $destinationFile -ToSession $session
            }
        }
        else {
            Write-Host "All files are already present in the remote folder on $ComputerName"
        }

        # Validate the copied content and list the remote folder contents
        $validationResult = Invoke-Command -Session $session -ScriptBlock {
            param($RemotePath)

            if (Test-Path $RemotePath) {
                Get-ChildItem -Path $RemotePath -Recurse
                return $true
            }
            else {
                return $false
            }
        } -ArgumentList $RemotePath

        # Output the remote folder contents
        if ($validationResult -eq $true) {
            Write-Host "Contents of the remote folder on $ComputerName"
            $validationResult
        }
        else {
            Write-Host "Failed to copy the contents to the remote folder on $ComputerName."
        }

        return $validationResult
    }
    finally {
        Start-Sleep -Seconds 2
        Remove-PSSession -Session $session
    }
}


$servers = get-content C:\temp\servers.txt
$Results = $null
$Results = @()



foreach ($server in $servers) {
    Write-Host "Processing server: $server"
    $cred = set-credential -computername $server
    $copy = Copy-TrendFolder -ComputerName $server -Credential $cred    
    $uninstall = Uninstall-TrendMicro -ComputerName $server -Credentials $cred
    $Install = Install-DeepSecurityAgent -RemoteComputerName $server -Credential $server
    $Obj = New-Object -TypeName PSOBject
    $Obj | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $server
    $Obj | Add-Member -MemberType NoteProperty -Name "Copy Trend Folder" -Value $copy
    $Obj | Add-Member -MemberType NoteProperty -Name "Install Trend" -Value $Install.Status
    $Obj | Add-Member -MemberType NoteProperty -Name "DSA Output" -Value $Install.Output
    $Results += $Obj

}

$Results

