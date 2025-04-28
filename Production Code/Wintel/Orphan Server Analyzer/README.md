# Orphan Server Analyzer

## Overview
This folder contains PowerShell scripts designed for comprehensive server analysis for orphaned servers. This focuse on retrieving domain group members and collecting detailed server information.

## Scripts

### 1. Get-DomainGroupMembers.ps1

#### Purpose
A PowerShell function to retrieve members of a specified domain group, providing detailed information about group composition.

#### Function Signature
```powershell
Get-DomainGroupMembers -DomainGroup "DOMAIN\GroupName"
```

#### Parameters
- `DomainGroup` (Mandatory): 
  - Format: `DOMAIN\GroupName`
  - Example: `CONTOSO\Domain Admins`

#### Dependencies
- Requires Thycotic credential retrieval script located at `D:\Thycotic\Get-thycoticCredentials.ps1` Shavlik servers have this script available.
- This script is designed to be run on LDN1WS7001
- Requires Active Directory PowerShell Module
- Requires network access to domain controller

#### Flow
1. Validate domain group name format
2. Retrieve credentials using Thycotic script
3. Find Primary Domain Controller (PDC)
4. Query group members using AD cmdlets
5. Return list of group members with Name, SamAccountName, and ObjectClass

#### Error Handling
- Validates credential script existence
- Handles invalid domain\group format
- Captures and reports errors during group member retrieval

#### Usage Example
```powershell
$members = Get-DomainGroupMembers -DomainGroup "CONTOSO\Domain Admins"
$members | Format-Table
```

### 2. Get-ServerInfo.ps1

#### Purpose
A comprehensive script for collecting detailed information about remote Windows servers, including system details, user groups, installed applications, and more. This script is designed to help wintel engineer analyze a orphan server to determine owners and its use.

#### Dependencies
- Requires `Get-DomainGroupMembers.ps1` (imported within the script)
- Requires Thycotic credential retrieval script
- This script is designed to be run on LDN1WS7001
- Requires WMI and Active Directory PowerShell modules
- Requires a text file `C:\temp\input.txt` containing server names to analyze

#### Input
- `C:\temp\input.txt`: A text file with server names, one per line

#### Output
- Generates detailed text reports for each server in `C:\temp\server_[SERVERNAME].txt`

#### Collected Information
1. Server Details
   - Hostname
   - Operating System
   - Hardware Information
   - Domain

2. User and Access Groups
   - Local Administrators
   - Remote Desktop Users
   - Domain Group Memberships

3. System Inventory
   - User Profiles
   - Installed Applications
   - Installed Roles
   - Local and Network Shares
   - Disk Information

#### Flow
1. Read server list from input file
2. Establish remote PowerShell session for each server
3. Collect comprehensive server information
4. Retrieve domain group memberships for non-local accounts
5. Generate detailed text report
6. Close remote session

#### Usage
```powershell
# Ensure C:\temp\input.txt is populated with server names
.\Get-ServerInfo.ps1
```

## Security and Credential Management
Both scripts use a centralized credential retrieval mechanism via the Thycotic script, ensuring secure and consistent authentication across server interactions.

## Limitations
- Requires network connectivity to target servers
- Depends on external credential retrieval script
- Requires appropriate user permissions for remote information gathering

## Recommended Permissions
- Domain User with Read access to Active Directory
- Local Administrator or equivalent permissions on target servers
