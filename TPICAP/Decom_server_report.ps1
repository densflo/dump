# Import DNSServer module
Import-Module DNSServer -ErrorAction Ignore 

if (-not (Get-Module DNSServer)) { 
    throw 'The Windows Feature "DNS Server Tools" is not installed.' 
}

# Define the server names
$servers = @(
    "NJCPADPDDC01", "NJCPADPDDC03", "NJCPADPCDS01", "NJCPADPCDS03", "NJCPADPCDS05", 
    "NJCPADPCDS07", "NJCPADPCDS09", "NJCPADPCDS11", "NJCPADPCDS13", "NJCPADPCDS15", 
    "NJCPADPCDS17", "NJCPADPCDS19", "NJCPADPCDS21", "NJCPADPCDS23", "NJCPADPCDS25", 
    "NJCPADPCDS27", "NJCPADPDMP01", "NJCPADPENT01", "NJCPADPENT03", "NJCPADPENT05", 
    "NJCPADPENT07", "NJCPADPETC01", "NJCPADPUSFI01", "NJCPADPUSFI03", "NJCPADPSQLCL101", 
    "NJCPADPSVR01", "NJCPADPWEB01", "NJCPADPADM1", "NJCPADPADM01", "NJCPADPDIR01", "NJCPADPLIQ01"
)

# Prepare an array to hold the results
$results = @()

# Loop over the server names
foreach ($server in $servers) {
    # Initialize the result object
    $result = [PSCustomObject]@{
        ServerName = $server
        ComputerObject = $null
        Groups = @()
        DNSRecord = $null
    }

    # Try to find a computer with this name
    $computer = Get-ADComputer -Filter { Name -eq $server } -ErrorAction SilentlyContinue
    if ($computer) {
        $result.ComputerObject = $computer.Name
    }

    # Try to find groups containing this name
    $groups = Get-ADGroup -Filter { Name -like "*$server*" } -ErrorAction SilentlyContinue
    if ($groups) {
        foreach ($group in $groups) {
            $result.Groups += $group.Name
        }
    } else {
        $result.Groups = "No group found"
    }

    # Check for DNS record
    try {
        $dnsRecord = Resolve-DnsName -Name $server -Type A -ErrorAction SilentlyContinue
        if ($dnsRecord) {
            $result.DNSRecord = $dnsRecord.IPAddress
        } else {
            $result.DNSRecord = "No record"
        }
    }
    catch {
        $result.DNSRecord = "Error"
    }

    # Add the result to the results array
    $results += $result
}

# Output the results as a table
$results | Format-Table