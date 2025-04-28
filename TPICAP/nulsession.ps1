# List of server names
$servers = @(
    "BOCPINFFPS02",
    "TORPINFFPS02",
    "HOUPINFFPS01",
    "DURPINFFSH02",
    "TORPINFFPS01",
    "LOUPINFFPS01",
    "LOUPINFFPS02"
)

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

# Initialize an empty array to hold results
$results = @()

# Loop through each server
foreach ($server in $servers) {
    $session = Get-RemoteSession -Server $server
    # Execute the code on the remote server
    $result = Invoke-Command -Session $session -ScriptBlock {
        $registryPath = "HKLM:\System\CurrentControlSet\Control\LSA"
        $valueName = "RestrictAnonymous"
        $value = 1

        if (Test-Path $registryPath) {
            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type DWORD
            return @{
                Server = $env:COMPUTERNAME
                NullSessionStatus = "Disabled"
            }
        } else {
            return @{
                Server = $env:COMPUTERNAME
                NullSessionStatus = "Registry path not found"
            }
        }
    }
    Remove-PSSession $session
    # Add the result to the results array
    $results += $result
}

# Convert the results array to a table and output it
$results | Format-Table -Property Server, NullSessionStatus -AutoSize
