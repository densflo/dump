function Add-DiskSpaceInfo {
    param(
        [string]$InputCsvPath,
        [string]$OutputCsvPath
    )

    $csvData = Import-Csv -Path $InputCsvPath -Delimiter ';'

    $outputData = foreach ($row in $csvData) {
        $outputString = $row.svc_plugin_output

        # Initialize variables with default values
        $freeSpaceGB = -1
        $isLessThan15GB = $false

        # Use regex to extract total and used space
        if ($outputString -match 'Used:.*?- ([\d\.]+) GiB of ([\d\.]+) GiB') {
            $usedGB = [double]$matches[1]
            $totalGB = [double]$matches[2]
            $freeSpaceGB = $totalGB - $usedGB
            $isLessThan15GB = $freeSpaceGB -lt 15
        }

        # Add the new columns to the existing row object
        $row | Add-Member -MemberType NoteProperty -Name "Free Disk Space (GB)" -Value $freeSpaceGB
        $row | Add-Member -MemberType NoteProperty -Name "Less Than 15GB Free" -Value $isLessThan15GB

        # Output the modified row
        $row
    }

    $outputData | Export-Csv -Path $OutputCsvPath -Delimiter ';' -NoTypeInformation
}

# Example Usage (You can test with your actual file)
# Add-DiskSpaceInfo -InputCsvPath "input.csv" -OutputCsvPath "output.csv"
