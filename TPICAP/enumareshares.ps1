function Get-RemoteSession {
    param (   
        [Parameter(Mandatory = $true, ParameterSetName = "Server", HelpMessage = "PMS Account.")]
        [String] $Server
    )
    $cred = D:\Thycotic\Get-thycoticCredentials.ps1 -server $server
    $securePassword = ConvertTo-SecureString $cred.password -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential ($cred.username, $securePassword)
    return New-PSSession -ComputerName $server -Credential $psCred
}

$servers = 'C:\Input\servers.txt'
$proc = Start-Process -filepath Notepad.exe -ArgumentList $servers -PassThru
$proc | Wait-Process
Write-Host "Notepad closed, proceeding with the rest of the script"
$servers = Get-Content "C:\input\servers.txt"

$ntfsResults = @()
$shareResults = @()

foreach ($server in $servers) {
    Write-Host "Connecting to $server"
    $session = Get-RemoteSession -Server $server
    $serverResults = Invoke-Command -Session $session -ScriptBlock {
        param($server)
        $ntfsResults = @()
        $shareResults = @()
        $shares = Get-SmbShare
            foreach ($share in $shares) {
                if ($share.Name.EndsWith('$')) {
                    continue
                } 
                $sharePermissions = Get-SmbShareAccess -Name $share.Name
                $ntfsPermissions = get-acl -path $share.Path
                foreach ($sharePermission in $sharePermissions) {
                    $shareResult = New-Object PSObject -Property @{
                        'Server' = $server
                        'Share' = $share.Name
                        'Identity' = $sharePermission.AccountName
                        'SharePermission' = $sharePermission.AccessControlType
                        'ShareAccessRight' = $sharePermission.AccessRight
                    }
                    $shareResults += $shareResult
                }
                foreach ($ntfsPermission in $ntfsPermissions.Access) {
                    $ntfsResult = New-Object PSObject -Property @{
                        'Server' = $server
                        'Share' = $share.Name
                        'NTFSPermission' = $ntfsPermission.FileSystemRights
                        'Identity' = $ntfsPermission.IdentityReference
                    }
                    $ntfsResults += $ntfsResult
                }
            }
        return @{
            'NtfsResults' = $ntfsResults
            'ShareResults' = $shareResults
        }
    } -ArgumentList $server
    $ntfsResults += $serverResults.NtfsResults
    $shareResults += $serverResults.ShareResults
}

# Export the results to separate CSV files
$ntfsResults | Export-Csv -Path "C:\outputs\ntfs_permision.csv" -NoTypeInformation
$shareResults | Export-Csv -Path "C:\outputs\share_permision.csv" -NoTypeInformation