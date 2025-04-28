# Import the Active Directory module to ensure access to AD-specific cmdlets
Import-Module ActiveDirectory

function Get-RemoteSession {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Server", HelpMessage = "PMS Account.")]
        [String] $Server
    )
    Write-Host "Fetching credentials for $Server"
    $cred = D:\Thycotic\Get-thycoticCredentials.ps1 -server $Server
    $securePassword = ConvertTo-SecureString $cred.password -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential ($cred.username, $securePassword)
    Write-Host "Creating PSSession for $Server"
    return New-PSSession -ComputerName $Server -Credential $psCred -ErrorAction SilentlyContinue
}


# Define the DNS record and server for resolution
$dnsRecord = "bulkmail.iwip.tpicap.com."
$dnsServer = "198.99.65.20"

# Get all domain controllers in the forest
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$allDomains = $forest.Domains | Select-Object -ExpandProperty Name

$results = foreach ($domain in $allDomains) {
    # Retrieve all DCs for the current domain
    $dcs = Get-ADDomainController -Filter * -Server $domain
    
    foreach ($dc in $dcs) {
        # Perform the DNS query from the target DC
        $session = Get-RemoteSession -server $dc.HostName
        try {
            $result = Invoke-Command -Session $session -ScriptBlock {
                Param($dnsRecord, $dnsServer)
                Resolve-DnsName -Name $dnsRecord -Server $dnsServer -ErrorAction Stop
            } -ArgumentList $dnsRecord, $dnsServer
            $status = "Success"
            write-host "Successfully Connected to $dc.Hostname"
            
        } catch {
            $result = $_.Exception.Message
            $status = "Failed"
            write-host "Error Connecting to $dc.Hostname"
        }
        Remove-PSSession -Session $session

        # Compile the results into a custom object
        [PSCustomObject]@{
            Domain       = $domain
            TargetDC     = $dc.HostName
            QueryRecord  = $dnsRecord
            DNSserver    = $dnsServer
            Resolution   = $status
            DNSresults   = "Type: $($result.Type) IPaddress: $($result.IPAddress)"
        }
    }
}

# Output the results as a table
$results | Format-Table -AutoSize
