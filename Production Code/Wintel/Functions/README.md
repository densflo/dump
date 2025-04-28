# PowerShell Functions Overview

This directory contains utility PowerShell functions for various administrative and data retrieval tasks.

## Get-A2RMData.ps1

### Function Description
`Get-A2RMData` is a PowerShell function designed to retrieve and display Configuration Management Database (CMDB) data for a specified computer from the A2RM API.

### Key Features
- Retrieves CMDB data for a local or specified computer
- Supports both verbose and standard output modes
- Validates and formats API response
- Displays comprehensive system and application information

### Parameters
- `ComputerName` (optional): 
  - Specifies the computer to lookup 
  - Defaults to local computer name if not provided
- `CurlPath` (optional):
  - Path to curl executable
  - Defaults to "curl.exe" in system PATH
- `Payload` (optional):
  - Switch to display the raw JSON payload at the beginning of the output.

### Usage Examples
```powershell
# Retrieve data for local computer
Get-A2RMData

# Retrieve data for a specific server
Get-A2RMData -ComputerName "SERVER01"

# Retrieve data for a specific server including the raw JSON payload
Get-A2RMData -ComputerName "SERVER01" -Payload
```

### Requirements
- Curl executable
- Network access to A2RM API
- Basic authentication credentials

### Output Details
Provides detailed information including:
- Basic host information
- Application instances
- Server details
- Tags
- Full JSON payload
- Device Host Data

## Load-FunctionScripts.ps1

### Function Description
`Load-FunctionScripts` is a PowerShell function designed to load PowerShell scripts from a specified directory. It also manages the configured function paths in the PowerShell profile.

### Key Features
- Loads .ps1 scripts from a specified folder
- Manages function paths in the PowerShell profile
- Supports adding, cleaning, and replacing function paths
- Provides feedback on loaded scripts and configured paths

### Parameters
- `FolderPath` (optional):
  - Specifies the path to the folder containing the .ps1 scripts.
- `Clean` (optional):
  - Switch to remove a configured path from the profile.
- `Add` (optional):
  - Switch to add a new path to the profile.
- `Replace` (optional):
  - Switch to replace the existing profile content with a new path.

### Usage Examples
```powershell
# Load scripts from a specific folder
Load-FunctionScripts -FolderPath "C:\path\to\scripts"

# Clean a configured path from the profile
Load-FunctionScripts -Clean

# Add a new path to the profile
Load-FunctionScripts -FolderPath "C:\new\path" -Add

# Replace the profile content with a new path
Load-FunctionScripts -FolderPath "C:\new\path" -Replace
```

### Requirements
- PowerShell profile configured
- Valid folder path containing .ps1 scripts

### Output Details
- Displays loaded function paths
- Provides feedback on profile modifications

### Flowchart
[Flowchart for Load-FunctionScripts.ps1 will be added here]

## Unlock-User.ps1

### Function Description
`Unlock-User` is an advanced Active Directory user account unlocking utility that:
- Checks and unlocks locked user accounts
- Identifies lockout sources
- Terminates active user sessions

### Parameters
- `domainName` (mandatory): Active Directory domain name
- `userName` (mandatory): User account to unlock
- `cred` (mandatory): PowerShell credential object for authentication
- `daysBack` (optional, default 7): Number of days to search for lockout events

### Key Features
- Supports multiple domain controllers
- Searches for lockout events
- Logs off active user sessions
- Provides detailed lockout information

### Usage Example
```powershell
$credential = Get-Credential
Unlock-User -domainName "corp.ad.tullib.com" -userName "d_flores" -cred $credential
```

### Requirements
- Active Directory PowerShell Module
- Administrative credentials
- Network access to domain controllers

### Output Details
- Displays lockout status
- Provides lockout source information
- Logs off active user sessions

### Flowchart
[Flowchart for Unlock-User.ps1 will be added here]

## General Dependencies
- PowerShell 5.0 or higher
- Active Directory PowerShell Module
- Network connectivity
- Appropriate user permissions
