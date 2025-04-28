# FileshareLogger Documentation

## Overview
The FileshareLogger is a set of PowerShell scripts designed to log and track server connections and authentication events and manage connection logs efficiently. This script is developed to answer the question of who is connecting to a Windows file share server and using its files. This script creates Excel files that can be attached to change tickets to prove that due diligence was performed in determining who will be impacted during a file share server change.

## Scripts

### 1. logauthentications.ps1
#### Purpose
Captures and logs authentication events from the Windows Security log, focusing on specific logon types.

#### Functionality
- Retrieves Windows security events with ID 4624 (Account Logon)
- Filters logon events for interactive, network, batch, and service logon types
- Resolves IP addresses to Fully Qualified Domain Names (FQDN)
- Exports log data to a CSV file in `C:\logs`

#### Key Features
- Logs up to 500 most recent authentication events within the last 94 hours
- Captures details such as:
  - Timestamp
  - Logon Type
  - User
  - Target Computer
  - Source IP
  - Source Computer
  - Logon Process
  - Resolved FQDN

#### Dependencies
- Windows PowerShell
- Windows Security Event Log
- Network DNS resolution capabilities

#### Error Handling
- Creates log directory if it doesn't exist
- Handles IP address resolution gracefully
- Provides error messages for log processing failures

### 2. Logconnections.ps1
#### Purpose
Tracks and logs new server connections across network shares.

#### Functionality
- Captures current server connections using CIM (Common Information Model)
- Resolves computer names to FQDNs
- Logs unique connections to a daily CSV file
- Tracks network share usage and user access patterns

#### Key Features
- Resolves IP addresses to FQDNs using a specific DNS server
- Retrieves share paths
- Compares current connections with previously logged connections
- Logs only new, unique connections

#### Dependencies
- Windows PowerShell
- SMB (Server Message Block) module
- DNS resolution
- Specific DNS server: `LDN1WS0060.corp.ad.tullib.com`

#### Error Handling
- Creates log directory if it doesn't exist
- Handles share path and FQDN resolution with warning messages
- Gracefully manages scenarios with no new connections

### 3. Merge-UniqueLogConnections.ps1
#### Purpose
Consolidates CSV log files and records only unique computer names and usernames.

#### Functionality
- Scans `C:\logs` directory for CSV files
- Excludes authentication log files
- Selects unique entries based on ComputerName and UserName
- Exports unique connections to a new CSV file

#### Key Features
- Filters out duplicate connection entries
- Creates a consolidated log of unique connections
- Provides summary information about processed files

#### Dependencies
- Windows PowerShell
- Existing CSV log files in `C:\logs`

#### Error Handling
- Checks for log directory existence
- Handles scenarios with no CSV files to process

### 4. scheduled task.ps1
#### Purpose
Creates a scheduled task to run Logconnections.ps1 periodically.

#### Functionality
- Sets up a scheduled task to execute Logconnections.ps1
- Configures task to run every 30 minutes
- Uses SYSTEM account for execution
- Ensures high-privilege execution

#### Key Features
- Removes existing task if present
- Creates new scheduled task
- Configures task with specific execution parameters

#### Dependencies
- Windows Task Scheduler
- PowerShell
- Logconnections.ps1 script

#### Execution Details
- Runs under NT AUTHORITY\SYSTEM account
- Uses highest privilege level
- Bypasses execution policy for the script

## Workflow
1. `scheduled task.ps1` sets up periodic execution of `Logconnections.ps1`
2. `Logconnections.ps1` logs new server connections
3. `Merge-UniqueLogConnections.ps1` can be used to consolidate logs
4. `logauthentications.ps1` can be run separately to log authentication events

## Log Storage
- All logs are stored in `C:\logs`
- Logs are named with date-based conventions
- CSV format for easy analysis and import

## Recommended Usage
- Ensure appropriate permissions for log directory and script execution
- Regularly review and archive logs
- Monitor system resources during log collection
