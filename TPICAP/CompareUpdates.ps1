$computers = @('LDN1WS9765', 'LDN2WS9783', 'LDN2WS9781')

# Script Block to retrieve updates with HotFixID, Description, and InstalledOn
$UpdateScriptBlock = {
    Get-HotFix | Select-Object -Property HotFixID, Description, InstalledOn
}

# Retrieve updates from each computer and store in hashtable
$updateResults = @{}
foreach ($computer in $computers) {
    $updateResults[$computer] = Invoke-Command -ComputerName $computer -ScriptBlock $UpdateScriptBlock
}

# Create a unique list of all KB articles and their descriptions
$allKbsWithDetails = @{}
foreach ($computerUpdates in $updateResults.Values) {
    foreach ($update in $computerUpdates) {
        if (-not $allKbsWithDetails.ContainsKey($update.HotFixID)) {
            $allKbsWithDetails[$update.HotFixID] = @{
                'Description' = $update.Description
                'InstalledOn' = @($update.InstalledOn)
            } 
        } else {
            $allKbsWithDetails[$update.HotFixID]['InstalledOn'] += $update.InstalledOn
        }
    }
}

# Filter out the KBs that are installed on all computers
$allKbs = $allKbsWithDetails.Keys | Where-Object {
    $kb = $_
    $totalOccurrences = ($updateResults.Values | Where-Object { $_.HotFixID -eq $kb } | Measure-Object).Count
    $totalOccurrences -ne $computers.Length
} | Sort-Object

# Build the comparison table
$comparisonTable = foreach ($kb in $allKbs) {
    $props = @{
        KB          = $kb
        Description = $allKbsWithDetails[$kb]['Description']
    }
    foreach ($computer in $computers) {
        $update = $updateResults[$computer] | Where-Object { $_.HotFixID -eq $kb }
        if ($update) {
            $props[$computer] = "Installed"
            $props["${computer}_Date"] = ($update.InstalledOn -as [datetime]).ToString('yyyy-MM-dd')
        } else {
            $props[$computer] = "Missing"
            $props["${computer}_Date"] = $null
        }
    }

    $kbStatus = New-Object -TypeName PSObject -Property $props
    $kbStatus
}

# Output the comparison table
Write-Host "Comparison of updates between the servers:"
$properties = @('KB', 'Description') + $computers + $computers.ForEach({ $_ + "_Date" })
$comparisonTable | Format-Table -Property $properties -AutoSize | Out-Host
