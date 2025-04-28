Function Convert-OutputForCSV {
    <#
        .SYNOPSIS
            Provides a way to expand collections in an object property prior
            to being sent to Export-Csv.

        .DESCRIPTION
            Provides a way to expand collections in an object property prior
            to being sent to Export-Csv. This helps to avoid the object type
            from being shown such as system.object[] in a spreadsheet.

        .PARAMETER InputObject
            The object that will be sent to Export-Csv

        .PARAMETER OutPropertyType
            This determines whether the property that has the collection will be
            shown in the CSV as a comma delimited string or as a stacked string.

            Possible values:
            Stack
            Comma

            Default value is: Stack

        .EXAMPLE
            $Output = 'PSComputername','IPAddress','DNSServerSearchOrder'
            Get-WMIObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" |
            Select-Object $Output | Convert-OutputForCSV | 
            Export-Csv -NoTypeInformation -Path NIC.csv    

            Description
            -----------
            Using a predefined set of properties to display ($Output), data is collected from the 
            Win32_NetworkAdapterConfiguration class and then passed to the Convert-OutputForCSV
            function which expands any property with a collection so it can be read properly prior
            to being sent to Export-Csv. Properties that had a collection will be viewed as a stack
            in the spreadsheet.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline)]
        [PSObject]$InputObject,
        [Parameter()]
        [ValidateSet('Stack', 'Comma')]
        [String]$OutputPropertyType = 'Stack'
    )

    Process {
        if (-not $InputObject) {
            Write-Warning "InputObject is null or empty."
            return
        }

        $properties = $InputObject.PSObject.Properties
        $customObject = @{}

        foreach ($prop in $properties) {
            if ($prop.Value -is [System.Collections.IEnumerable] -and ($prop.Value -isnot [String])) {
                if ($OutputPropertyType -eq 'Comma') {
                    $customObject[$prop.Name] = ($prop.Value -join ', ')
                } else {
                    $customObject[$prop.Name] = ($prop.Value | Out-String).Trim()
                }
            } else {
                $customObject[$prop.Name] = $prop.Value
            }
        }

        [PSCustomObject]$customObject
    }
}
