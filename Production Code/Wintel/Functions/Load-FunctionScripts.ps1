function Load-FunctionScripts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$FolderPath,

        [Parameter(Mandatory = $false)]
        [switch]$Clean,

        [Parameter(Mandatory = $false)]
        [switch]$Add,

        [Parameter(Mandatory = $false)]
        [switch]$Replace
    )

    $profilePath = $PROFILE
    if (-not (Test-Path $profilePath)) {
        $profilePath = Join-Path $env:USERPROFILE 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'
    }
    $defaultFunctionPath = "$(Join-Path $env:USERPROFILE 'OneDrive - TP ICAP\Documents\Code\Functions')"
    
    # Load configured paths from profile
    $profileContent = Get-Content $profilePath -ErrorAction SilentlyContinue
    $configuredPaths = @()
    if ($profileContent) {
        foreach ($line in $profileContent) {
            if ($line -match "Load-FunctionScripts -FolderPath '([^']+)'") {
                $configuredPaths += $Matches[1]
            }
        }
    }
    if (-not $configuredPaths) {
        $configuredPaths = @($defaultFunctionPath)
    }


    if ($Clean) {
        if ($configuredPaths) {
            Write-Host "Configured function paths:"
            for ($i = 0; $i -lt $configuredPaths.Length; $i++) {
                Write-Host "$($i+1): $($configuredPaths[$i])"
            }

            $removePath = Read-Host "Enter the number of the path to remove (or press Enter to skip)"
            if ($removePath) {
                if ($removePath -match '^\d+$' -and $removePath -ge 1 -and $removePath -le $configuredPaths.Length) {
                    $pathToRemove = $configuredPaths[$removePath - 1]
                    Write-Host "Removing path: $pathToRemove"
                    
                    # Read the profile content
                    $profileContent = Get-Content $profilePath
                    
                    # Filter out the line containing the path to remove
                    $newProfileContent = $profileContent | Where-Object {$_ -notlike "*Load-FunctionScripts -FolderPath '$pathToRemove'*" }
                    
                    # Write the modified content back to the profile
                    Set-Content -Path $profilePath -Value ($newProfileContent -join "`n")
                    
                    Write-Host "Path '$pathToRemove' removed from profile."
                } else {
                    Write-Host "Invalid input. Please enter a valid number."
                }
            }
        } else {
            Write-Host "No function paths configured."
        }
        return
    }

    if ($Add) {
        if ($FolderPath) {
            # Add logic to add the folder to the profile file
            Write-Host "Adding path '$FolderPath' to profile."
            $profileContent = Get-Content $profilePath
            $newContent = $profileContent + "`nLoad-FunctionScripts -FolderPath '$FolderPath'"
            Set-Content -Path $profilePath -Value $newContent
            Write-Host "Path '$FolderPath' added to profile."
        } else {
            Write-Host "Please provide a folder path with -add switch."
        }
        return
    }

    if ($Replace) {
         if ($FolderPath) {
            # Replace the content of the profile file with the new path
            Write-Host "Replacing profile content with path '$FolderPath'."
            $newContent = "Load-FunctionScripts -FolderPath '$FolderPath'"
            Set-Content -Path $profilePath -Value $newContent
            # Update configured paths
            $configuredPaths = @($FolderPath)
            Write-Host "Profile content replaced with path '$FolderPath'."
        } else {
            Write-Host "Please provide a folder path with -replace switch."
        }
        return
    }

    if (-not $Clean) {
         Write-Host "Module location: $($configuredPaths[0])"
        if ($configuredPaths.Count -gt 1) {
            Write-Host "Additional loaded folders:"
            for ($i = 1; $i -lt $configuredPaths.Length; $i++) {
                Write-Host "- $($configuredPaths[$i])"
            }
        }
    }

    if ($FolderPath) {
        if (Test-Path $FolderPath) {
            Get-ChildItem -Path $FolderPath -Filter *.ps1 | ForEach-Object {
                . $_.FullName
            }
            Write-Host "PowerShell functions from $FolderPath have been loaded."
        } else {
            Write-Host "Warning: The specified function path ($FolderPath) does not exist."
        }
    } else {
        foreach ($path in $configuredPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Filter *.ps1 | ForEach-Object {
                    . $_.FullName
                }
                 Write-Host "PowerShell functions from $path have been loaded."
            } else {
                Write-Host "Warning: The specified function path ($path) does not exist."
            }
        }
    }
}
