# Path to the file to copy
$SourceFile = "C:\ProgramData\checkmk\agent\plugins\ad_replication.bat"

# Define log file path
$LogFile = "C:\temp\Copy-ADReplication-$(Get-Date -Format 'yyyyMMddHHmmss').log"

# Function to write to log and console
function Write-Log {
    param (
        [string]$Message,
        [string]$LogType = "INFO"
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "$Timestamp [$LogType] - $Message"

    Write-Host $LogEntry
    Out-File -FilePath $LogFile -Append -InputObject $LogEntry -Encoding UTF8
}

Write-Log "Starting script"

# Open the file in Notepad
Write-Log "Opening $SourceFile in Notepad"
notepad $SourceFile

# Wait for Notepad to close
Write-Host "Waiting for Notepad to close..."
while (Get-Process -Name notepad -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 5
}

# Path to the file containing the list of remote computers
$ComputerListFile = "C:\temp\input.txt"

# Read the list of remote computers from the file
try {
    $Computers = Get-Content $ComputerListFile -ErrorAction Stop
}
catch {
    Write-Error "Error reading computer list from ${ComputerListFile}: $($_.Exception.Message)"
    exit 1
}

# Check if the source file exists
if (!(Test-Path $SourceFile)) {
    Write-Error "Source file not found: $SourceFile"
    Write-Log "Error reading computer list from ${ComputerListFile}: $($_.Exception.Message)" "ERROR"
    exit 1
}

# Iterate through the list of computers and copy the file
foreach ($Computer in $Computers) {
    # Trim any whitespace from the computer name
    $Computer = $Computer.Trim()

    # Check if the computer name is empty
    if ([string]::IsNullOrEmpty($Computer)) {
        continue
    }

    Write-Log "Processing computer: $Computer"

    # Path to the destination directory on the remote computer
    $DestinationPath = Join-Path -Path "\\$Computer\C$\ProgramData" -ChildPath "checkmk\agent\plugins"

     # Check if the destination directory exists
    Write-Log "Checking if destination directory exists: $DestinationPath"
    if (!(Test-Path $DestinationPath)) {
        Write-Log "Destination directory does not exist. Attempting to create it."
        try {
            New-Item -ItemType Directory -Path $DestinationPath -Force -ErrorAction Stop | Out-Null
            Write-Log "Successfully created directory ${DestinationPath} on ${Computer}"
        }
        catch {
            Write-Log "Failed to create directory ${DestinationPath} on ${Computer}: $($_.Exception.Message)" "WARNING"
            continue
        }
    }
    else {
        Write-Log "Destination directory exists."
    }

    # Copy the file to the remote computer
    Write-Log "Attempting to copy $SourceFile to $DestinationPath"
    try {
        Copy-Item -Path $SourceFile -Destination $DestinationPath -ErrorAction Stop
        Write-Log "Successfully copied $SourceFile to $DestinationPath"
    }
    catch {
        Write-Log "Error copying ${SourceFile} to ${DestinationPath}: $($_.Exception.Message)" "ERROR"
    }
}

Write-Log "File copy complete."
