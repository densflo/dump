#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Implements protection against CVE-2018-3639 - Speculative Store Bypass (Spectre Variant 4)
.DESCRIPTION
    Addresses Microsoft Windows Security Update Registry Key Configuration Missing (ADV180012) by implementing
    required registry keys based on processor type. Compatible with Windows Server 2008 and above,
    supporting both 32-bit and 64-bit architectures.

.NOTES
    Filename: CV20183639.ps1
    Author: Cline
    Requires: PowerShell 2.0 or higher (for Windows Server 2008 compatibility)
    Supported OS: Windows Server 2008 and above, Windows 7 and above
    Architecture: x86 and x64
    CVE: CVE-2018-3639
    Microsoft Advisory: ADV180012
    Qualys QID: 91462
    Directed by: Dennis Jeffrey Flores
#>
#region Script Description
# Mitigates CVE-2018-3639 (Speculative Store Bypass, also known as Spectre Variant 4) by configuring the required registry settings.
# This script disables Speculative Store Bypass (SSB) to protect against Spectre Variant 4.
# According to Microsoft, disabling SSB may have performance impacts.  Test thoroughly before deploying to production.
# The script sets the FeatureSettingsOverride and FeatureSettingsOverrideMask registry values in HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management.
# A system restart is required for the changes to take effect.
#endregion

# Ensure script runs on PowerShell 2.0 and above for maximum compatibility
if ($PSVersionTable.PSVersion.Major -lt 2) {
    Write-Error "This script requires PowerShell 2.0 or higher."
    exit 1
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Initialize logging with compatibility for older systems
$LogPath = Join-Path "C:\temp" "SpectreMeltdownV4_Protection.log"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Global:OSVersion = $null
$Global:Is64Bit = $null

function Write-Log {
    param($Message)
    $LogMessage = "[$Timestamp] $Message"
    try {
        Add-Content -Path $LogPath -Value $LogMessage -ErrorAction Stop
        Write-Host $LogMessage
    }
    catch {
        Write-Host "Failed to write to log file: $_"
        Write-Host $LogMessage
    }
}

function Test-AdminPrivileges {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Log "Error checking admin privileges: $_"
        return $false
    }
}

function Test-SystemCompatibility {
    try {
        # Get OS version information
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $Global:OSVersion = [Version]$os.Version
        $Global:Is64Bit = [Environment]::Is64BitOperatingSystem

        # Check OS version compatibility
        $minVersion = [Version]"6.0.6001" # Windows Server 2008
        if ($Global:OSVersion -lt $minVersion) {
            throw "This script requires Windows Server 2008 or later. Current version: $($os.Caption)"
        }

        Write-Log "System Information:"
        Write-Log "OS: $($os.Caption)"
        Write-Log "Version: $($Global:OSVersion)"
        Write-Log "Architecture: $(if ($Global:Is64Bit) {'64-bit'} else {'32-bit'})"
        Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"

        return $true
    }
    catch {
        Write-Log "Error checking system compatibility: $_"
        return $false
    }
}

function Get-ProcessorDetails {
    try {
        # Use older WMI query method for compatibility
        $processor = Get-WmiObject -Class Win32_Processor -ErrorAction Stop
        
        # Some older systems might have multiple processors
        if ($processor -is [array]) {
            $processor = $processor[0]
        }

        # Get processor ID using compatible method
        $processorId = $null
        try {
            $processorId = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment" -ErrorAction Stop).PROCESSOR_IDENTIFIER
        }
        catch {
            $processorId = $processor.Name
        }

        Write-Log "Detected Processor: $processorId"
        Write-Log "Manufacturer: $($processor.Manufacturer)"
        Write-Log "Architecture: $(if ($Global:Is64Bit) {'64-bit'} else {'32-bit'})"
        
        return @{
            Type = if ($processor.Manufacturer -match "AMD") { "AMD" } else { "Intel" }
            Details = $processorId
        }
    }
    catch {
        throw "Failed to detect processor details: $_"
    }
}

function Set-SpectreMeltdownProtection {
    # Define the registry path
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
 
    # Get the number of logical processors
    $cpuInfo = Get-WmiObject Win32_Processor
    $logicalProcessors = $cpuInfo.NumberOfLogicalProcessors
    $physicalProcessors = $cpuInfo.NumberOfCores
    $totalLogicalProcessors = 0
    foreach ($logicalProcessor in $logicalProcessors) {$totalLogicalProcessors += $logicalProcessor}
    $totalphysicalProcessors =0
    foreach ($physicalProcessor in $physicalProcessors) {$totalphysicalProcessors += $physicalProcessor}
 
    # Check if Hyperthreading is enabled
    if ($totalLogicalProcessors -gt $totalphysicalProcessors) {
        # Hyperthreading is enabled, set FeatureSettingsOverride to 72
        Write-Log "Hyperthreading is enabled. Setting FeatureSettingsOverride to 72."
        Set-ItemProperty -Path $registryPath -Name "FeatureSettingsOverride" -Value 72
    } else {
        # Hyperthreading is disabled, set FeatureSettingsOverride to 8264
        Write-Log "Hyperthreading is disabled. Setting FeatureSettingsOverride to 8264."
        Set-ItemProperty -Path $registryPath -Name "FeatureSettingsOverride" -Value 8264
    }
 
    # Set FeatureSettingsOverrideMask to 3 regardless of Hyperthreading status
    Write-Log "Setting FeatureSettingsOverrideMask to 3."
    Set-ItemProperty -Path $registryPath -Name "FeatureSettingsOverrideMask" -Value 3
 
    # Optional: Restart the server to apply changes
    Write-Log "A system restart is required for these changes to take effect."
}

function Get-RegistryDWORDValue {
    param (
        [string]$Path,
        [string]$Name
    )

    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $value.$Name
    }
    catch {
        Write-Log "Failed to query registry value: $_"
        return $null
    }
}

function Test-Protection {
    try {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

        # Get registry values using the new helper function
        $override = Get-RegistryDWORDValue -Path $registryPath -Name "FeatureSettingsOverride"
        $mask = Get-RegistryDWORDValue -Path $registryPath -Name "FeatureSettingsOverrideMask"

        Write-Log "Current Settings:"
        Write-Log "FeatureSettingsOverride: $override"
        Write-Log "FeatureSettingsOverrideMask: $mask"

        if ($null -eq $override -or $null -eq $mask) {
            Write-Log "One or more registry values are missing"
            return $false
        }

        # Verify settings
        if ($override -ne 72) {
            Write-Log "FeatureSettingsOverride value is incorrect: $override (should be 72)"
            return $false
        }
        if ($mask -ne 3) {
            Write-Log "FeatureSettingsOverrideMask value is incorrect: $mask (should be 3)"
            return $false
        }

        return $true
    }
    catch {
        Write-Log "Error verifying CVE-2018-3639 protection: $_"
        return $false
    }
}

# Main execution block
try {
    Write-Log "Starting protection script for CVE-2018-3639 (Spectre Variant 4)"
    Write-Log "This script is compatible with Windows Server 2008 and above (32-bit and 64-bit)"

    # Check for admin privileges
    if (-not (Test-AdminPrivileges)) {
        throw "This script requires administrator privileges"
    }

    # Check system compatibility
    if (-not (Test-SystemCompatibility)) {
        throw "System compatibility check failed"
    }

    # Detect processor details (for logging purposes)
    $processorInfo = Get-ProcessorDetails
    Write-Log "Processor Type: $($processorInfo.Type)"
    Write-Log "Processor Details: $($processorInfo.Details)"

    # Apply protection (same settings for both AMD and Intel)
    Set-SpectreMeltdownProtection
    Write-Log "Applied CVE-2018-3639 protection settings"

    # Verify protection
    if (Test-Protection) {
        Write-Log "SUCCESS: CVE-2018-3639 mitigation verified successfully"
        Write-Log "System is now protected against Speculative Store Bypass (Spectre Variant 4)"
    }
    else {
        throw "CVE-2018-3639 protection verification failed"
    }
}
catch {
    Write-Log "ERROR: $_"
    throw $_
}
finally {
    Write-Log "Script execution completed"
    Write-Log "Log file location: $LogPath"
}
