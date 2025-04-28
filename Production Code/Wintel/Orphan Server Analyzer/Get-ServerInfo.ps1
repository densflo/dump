function Get-RemoteSession {
    param (   
        [Parameter(Mandatory = $true, ParameterSetName = "Server", HelpMessage = "Server name to connect to.")]
        [String] $Server
    )
    try {
        # Check if credential script exists
        $credScriptPath = "D:\Thycotic\Get-thycoticCredentials.ps1"
        if (-not (Test-Path $credScriptPath)) {
            throw "Credential retrieval script not found at $credScriptPath"
        }

        $cred = & $credScriptPath -server $server
        $securePassword = ConvertTo-SecureString $cred.password -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential ($cred.username, $securePassword)
        return New-PSSession -ComputerName $server -Credential $psCred -ErrorAction Stop
    }
    catch {
        Write-Error ("Failed to create remote session for {0}. Error: {1}" -f $server, $_.Exception.Message)
        return $null
    }
}

# Import the Get-DomainGroupMembers function
. .\Get-DomainGroupMembers.ps1

# Ensure temp directory exists
$tempDir = "C:\temp"
if (-not (Test-Path $tempDir)) {
    try {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    }
    catch {
        Write-Error "Could not create temp directory: $_"
        exit
    }
}

# Check input file exists
$inputFile = Join-Path $tempDir "input.txt"
if (-not (Test-Path $inputFile)) {
    Write-Error "Input file $inputFile not found. Please create the file with server names."
    exit
}

# Read server list
$Servers = Get-Content $inputFile

# Process each server
foreach ($Server in $Servers) {
    Write-Host "Processing $Server"
    
    # Establish remote session
    $Session = Get-RemoteSession -Server $Server
    
    if ($Session) {
        try {
            # Gather comprehensive server information
            $ServerInfo = Invoke-Command -Session $Session -ScriptBlock {
                # Function to convert WMI datetime
                function Convert-WmiDateTime {
                    param([string]$WmiDate)
                    try {
                        if (-not $WmiDate) { return "N/A" }
                        
                        # Extract date components
                        $year = $WmiDate.Substring(0, 4)
                        $month = $WmiDate.Substring(4, 2)
                        $day = $WmiDate.Substring(6, 2)
                        $hours = $WmiDate.Substring(8, 2)
                        $minutes = $WmiDate.Substring(10, 2)
                        $seconds = $WmiDate.Substring(12, 2)

                        # Create datetime object
                        $dateTime = Get-Date -Year $year -Month $month -Day $day -Hour $hours -Minute $minutes -Second $seconds

                        # Return formatted date
                        return $dateTime.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                    catch {
                        return "Invalid Date Format"
                    }
                }

                # Server Details
                $osInfo = Get-WmiObject Win32_OperatingSystem
                $computerInfo = Get-WmiObject Win32_ComputerSystem
                $biosInfo = Get-WmiObject Win32_BIOS


                # Get Local Administrators Group Members
                $adminGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators"
                $administrators = @($adminGroup.Invoke('Members') | ForEach-Object {
                    $path = ([ADSI]$_).Path
                    $name = $path.Split('/')[-1]
                    $isDomainGroup = $path -match "WinNT://([^/]+)/([^/]+)$"
                    $domain = if ($matches) { $matches[1] } else { $env:COMPUTERNAME }
                    $accountName = if ($matches) { $matches[2] } else { $name }
                    
                    [PSCustomObject]@{
                        Name = $name
                        Path = $path
                        Domain = $domain
                        AccountName = $accountName
                        IsLocal = if ($isDomainGroup) {$false} else {$true}
                    }
                })

                
                # Get Remote Desktop Users Group Members
                $rdpGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Remote Desktop Users"
                $rdpUsers = @($rdpGroup.Invoke('Members') | ForEach-Object {
                    $path = ([ADSI]$_).Path
                    $name = $path.Split('/')[-1]
                    $isDomainGroup = $path -match "WinNT://([^/]+)/([^/]+)$"
                    $domain = if ($matches) { $matches[1] } else { $env:COMPUTERNAME }
                    $accountName = if ($matches) { $matches[2] } else { $name }
                    
                    [PSCustomObject]@{
                        Name = $name
                        Path = $path
                        Domain = $domain
                        AccountName = $accountName
                        IsLocal = if ($isDomainGroup) {$false} else {$true}
                    }
                })

                # Rest of the server information gathering...
                $localProfiles = Get-WmiObject Win32_UserProfile | 
                    Select-Object @{Name='Username';Expression={$_.LocalPath.Split('\')[-1]}}, 
                                   @{Name='ProfilePath';Expression={$_.LocalPath}}, 
                                   @{Name='LastUsed';Expression={
                                       Convert-WmiDateTime $_.LastUseTime
                                   }}

                $installedApps = Get-WmiObject Win32_Product | 
                    Select-Object Name, Version, Vendor, 
                                   @{Name='InstallDate';Expression={
                                       if ($_.InstallDate) {
                                           $date = $_.InstallDate
                                           "$($date.Substring(0,4))-$($date.Substring(4,2))-$($date.Substring(6,2))"
                                       } else { 'Unknown' }
                                   }}

                $installedRoles = try {
                    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                        Get-WindowsFeature | Where-Object {$_.Installed} | 
                            Select-Object Name, DisplayName, Description
                    } else { 
                        @{Name = "Role retrieval unavailable"}
                    }
                }
                catch {
                    @{Name = "Role retrieval failed"}
                }

                $localShares = Get-WmiObject Win32_Share | 
                    Where-Object {$_.Type -ne 1} | 
                    Select-Object Name, Path, Description

                $networkShares = try {
                    Get-SmbShare -ErrorAction SilentlyContinue | 
                        Select-Object Name, Path, Description, ShareState, ShareType
                }
                catch {
                    @{Name = "Network share retrieval failed"}
                }

                $diskInfo = Get-WmiObject Win32_LogicalDisk | 
                    Select-Object @{Name='Drive';Expression={$_.DeviceID}}, 
                                   @{Name='Size';Expression={"{0:N2} GB" -f ($_.Size/1GB)}}, 
                                   @{Name='FreeSpace';Expression={"{0:N2} GB" -f ($_.FreeSpace/1GB)}}, 
                                   @{Name='PercentFree';Expression={"{0:N2}%" -f (($_.FreeSpace / $_.Size) * 100)}}, 
                                   FileSystem, 
                                   VolumeName

                [PSCustomObject]@{
                    ServerDetails = [PSCustomObject]@{
                        Hostname = $env:COMPUTERNAME
                        OperatingSystem = $osInfo.Caption
                        OSVersion = $osInfo.Version
                        Manufacturer = $computerInfo.Manufacturer
                        Model = $computerInfo.Model
                        SerialNumber = $biosInfo.SerialNumber
                        Domain = $computerInfo.Domain
                        TotalMemory = "{0:N2} GB" -f ($computerInfo.TotalPhysicalMemory / 1GB)
                    }
                    Administrators = $administrators
                    RemoteDesktopUsers = $rdpUsers
                    UserProfiles = $localProfiles
                    InstalledApplications = $installedApps
                    InstalledRoles = $installedRoles
                    LocalShares = $localShares
                    NetworkShares = $networkShares
                    DiskInfo = $diskInfo
                }
            }

            # Process domain groups for Administrators
            $adminDomainGroupMembers = @{}
            foreach ($admin in $ServerInfo.Administrators) {
                if (-not $admin.IsLocal) {
                    $groupPath = "$($admin.Domain)\$($admin.AccountName)"
                    try {
                        $members = Get-DomainGroupMembers -DomainGroup $groupPath
                        $adminDomainGroupMembers[$admin.Name] = $members
                    }
                    catch {
                        $adminDomainGroupMembers[$admin.Name] = "Failed to retrieve group members: $_"
                    }
                }
            }

            # Process domain groups for Remote Desktop Users
            $rdpDomainGroupMembers = @{}
            foreach ($rdpUser in $ServerInfo.RemoteDesktopUsers) {
                if (-not $rdpUser.IsLocal) {
                    $groupPath = "$($rdpUser.Domain)\$($rdpUser.AccountName)"
                    try {
                        $members = Get-DomainGroupMembers -DomainGroup $groupPath
                        $rdpDomainGroupMembers[$rdpUser.Name] = $members
                    }
                    catch {
                        $rdpDomainGroupMembers[$rdpUser.Name] = "Failed to retrieve group members: $_"
                    }
                }
            }

            # Create output file
            $outputPath = Join-Path $tempDir "server_$Server.txt"
            
            # Format and write detailed information
            $outputContent = @"
==================================================
SERVER INFORMATION REPORT FOR $Server
==================================================

SERVER DETAILS
--------------
Hostname:           $($ServerInfo.ServerDetails.Hostname)
Operating System:   $($ServerInfo.ServerDetails.OperatingSystem)
OS Version:         $($ServerInfo.ServerDetails.OSVersion)
Manufacturer:       $($ServerInfo.ServerDetails.Manufacturer)
Model:              $($ServerInfo.ServerDetails.Model)
Serial Number:      $($ServerInfo.ServerDetails.SerialNumber)
Domain:             $($ServerInfo.ServerDetails.Domain)
Total Memory:       $($ServerInfo.ServerDetails.TotalMemory)

==================================================
LOCAL ADMINISTRATORS GROUP MEMBERS
==================================================
$($ServerInfo.Administrators | ForEach-Object {
    $accountType = if ($_.IsLocal) { "Local Account" } else { "Domain Account" }
    "Name:          $($_.Name)`n" +
    "Type:          $accountType`n" +
    "Path:          $($_.Path)`n"
    
    if (-not $_.IsLocal -and $adminDomainGroupMembers.ContainsKey($_.Name)) {
        $groupMembers = $adminDomainGroupMembers[$_.Name]
        if ($groupMembers -is [string]) {
            "Group Members: $groupMembers`n"
        }
        else {
            "Group Members:`n" + ($groupMembers | ForEach-Object {
                "              - $($_.Name) ($($_.ObjectClass))`n"
            })
        }
    }
    "`n"
} | Out-String)

==================================================
REMOTE DESKTOP USERS GROUP MEMBERS
==================================================
$($ServerInfo.RemoteDesktopUsers | ForEach-Object {
    $accountType = if ($_.IsLocal) { "Local Account" } else { "Domain Account" }
    "Name:          $($_.Name)`n" +
    "Type:          $accountType`n" +
    "Path:          $($_.Path)`n"
    
    if (-not $_.IsLocal -and $rdpDomainGroupMembers.ContainsKey($_.Name)) {
        $groupMembers = $rdpDomainGroupMembers[$_.Name]
        if ($groupMembers -is [string]) {
            "Group Members: $groupMembers`n"
        }
        else {
            "Group Members:`n" + ($groupMembers | ForEach-Object {
                "              - $($_.Name) ($($_.ObjectClass))`n"
            })
        }
    }
    "`n"
} | Out-String)

==================================================
USER PROFILES
==================================================
$($ServerInfo.UserProfiles | ForEach-Object {
    "Username:       $($_.Username)`n" +
    "Profile Path:   $($_.ProfilePath)`n" +
    "Last Used:      $($_.LastUsed)`n"
} | Out-String)

==================================================
INSTALLED APPLICATIONS
==================================================
$($ServerInfo.InstalledApplications | 
    Sort-Object Name | 
    ForEach-Object {
        "Name:          $($_.Name)`n" +
        "Version:       $($_.Version)`n" +
        "Vendor:        $($_.Vendor)`n" +
        "Install Date:  $($_.InstallDate)`n"
    } | Out-String)

==================================================
INSTALLED ROLES
==================================================
$($ServerInfo.InstalledRoles | 
    ForEach-Object {
        "Name:          $($_.Name)`n" +
        "Display Name:  $($_.DisplayName)`n" +
        "Description:   $($_.Description)`n"
    } | Out-String)

==================================================
LOCAL SHARES
==================================================
$($ServerInfo.LocalShares | 
    ForEach-Object {
        "Name:          $($_.Name)`n" +
        "Path:          $($_.Path)`n" +
        "Description:   $($_.Description)`n"
    } | Out-String)

==================================================
NETWORK SHARES
==================================================
$($ServerInfo.NetworkShares | 
    ForEach-Object {
        "Name:          $($_.Name)`n" +
        "Path:          $($_.Path)`n" +
        "Description:   $($_.Description)`n" +
        "Share State:   $($_.ShareState)`n" +
        "Share Type:    $($_.ShareType)`n"
    } | Out-String)

==================================================
DISK INFORMATION
==================================================
$($ServerInfo.DiskInfo | 
    ForEach-Object {
        "Drive:         $($_.Drive)`n" +
        "Volume Name:   $($_.VolumeName)`n" +
        "File System:   $($_.FileSystem)`n" +
        "Total Size:    $($_.Size)`n" +
        "Free Space:    $($_.FreeSpace)`n" +
        "Percent Free:  $($_.PercentFree)`n"
    } | Out-String)
"@

            $outputContent | Out-File $outputPath -Encoding UTF8

            Write-Host "Server information for $Server saved to $outputPath"
        }
        catch {
            Write-Error "Error processing $Server : $_"
        }
        finally {
            # Close the remote session
            Remove-PSSession $Session
        }
    }
    else {
        Write-Warning "Could not establish session with $Server"
    }
}

Write-Host "Server information collection complete."
