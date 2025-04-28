# Path to the input text file
$inputFilePath = "C:\\temp\\input.txt"

Write-Host "Starting home drive copy process..." -ForegroundColor Green
Write-Host "Opening input file '$inputFilePath' in Notepad..." -ForegroundColor Cyan

# Open the input file in Notepad and get the process
$notepadProcess = Start-Process notepad $inputFilePath -PassThru

Write-Host "Waiting for Notepad to be closed..." -ForegroundColor Cyan

# Wait for the Notepad process to exit
Wait-Process -Id $notepadProcess.Id

Write-Host "Notepad closed. Processing input file..." -ForegroundColor Cyan

# Destination directory
$destinationDir = "\\\\ldnfs1.eur.ad.tullib.com\\serversupp$\\contractor"
Write-Host "Destination directory set to: $destinationDir" -ForegroundColor Cyan

# Check if the input file exists
if (!(Test-Path -Path $inputFilePath)) {
    Write-Error "Input file not found: '$inputFilePath'"
    exit 1
}

# Read user emails from the input file
$userEmails = Get-Content -Path $inputFilePath
Write-Host "Found $(($userEmails | Measure-Object).Count) email addresses to process" -ForegroundColor Cyan

# Check if the input file is empty
if (!$userEmails) {
    Write-Error "Input file is empty: '$inputFilePath'"
    exit 1
}

Write-Host "`nStarting to process each user..." -ForegroundColor Green

# Function to map network drive
function Map-NetworkDrive {
    param (
        [string]$Path,
        [string]$DriveLetter
    )
    try {
        # Remove existing mapping if it exists
        if (Test-Path "${DriveLetter}:") {
            Write-Host "Removing existing mapping for $DriveLetter" -ForegroundColor Cyan
            Remove-PSDrive -Name $DriveLetter -Force -ErrorAction SilentlyContinue
            net use "$($DriveLetter):" /delete /y 2>$null
        }
        
        Write-Host "Mapping $Path to $DriveLetter" -ForegroundColor Cyan
        $result = net use "$($DriveLetter):" "$Path" /PERSISTENT:NO
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully mapped drive $DriveLetter" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Failed to map drive $DriveLetter. Error: $result"
            return $false
        }
    }
    catch {
        Write-Warning "Error mapping drive $DriveLetter`: $_"
        return $false
    }
}

# Function to get folder size with error handling
function Get-FolderSize {
    param([string]$Path)
    try {
        # Use robocopy to get file list (more reliable for long paths)
        $tempFile = [System.IO.Path]::GetTempFileName()
        $null = robocopy $Path NULL /L /S /NJH /BYTES /FP /NC /NDL /XJ /R:0 /W:0 | Out-File $tempFile
        $size = Get-Content $tempFile | Where-Object { $_ -match '^\s+Files:\s+\d+\s+\d+$' } | 
                ForEach-Object { ($_ -split '\s+')[2] } | 
                Measure-Object -Sum | 
                Select-Object -ExpandProperty Sum
        Remove-Item $tempFile -Force
        return [math]::Round($size / 1GB, 2)
    }
    catch {
        Write-Warning "Could not calculate size for path '$Path': $_"
        return 0
    }
}

# Function to copy files with progress
function Copy-WithProgress {
    param(
        [string]$Source,
        [string]$Destination
    )
    
    try {
        # Use robocopy for the actual copy (better handling of long paths and errors)
        Write-Host "Starting robocopy process..." -ForegroundColor Cyan
        
        # Create base destination directory if it doesn't exist
        if (!(Test-Path -Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }

        # Use robocopy with progress
        $robocopyArgs = @(
            $Source
            $Destination
            '/E'        # Copy subdirectories, including empty ones
            '/Z'        # Copy files in restartable mode
            '/W:1'      # Wait time between retries
            '/R:1'      # Number of retries
            '/XJ'       # Exclude junction points
            '/NP'       # No progress - we'll handle our own progress display
            '/NDL'      # No directory list
            '/NC'       # No file classes
            '/BYTES'    # Show file sizes in bytes
            '/TEE'      # Output to console window and log file
        )

        $process = Start-Process robocopy -ArgumentList $robocopyArgs -NoNewWindow -PassThru -Wait
        
        # Check robocopy exit code (0-7 are success codes)
        if ($process.ExitCode -lt 8) {
            Write-Host "Copy completed successfully" -ForegroundColor Green
            
            # Get list of copied files for report
            $files = Get-ChildItem -Path $Destination -Recurse -File -ErrorAction SilentlyContinue
            return $files
        }
        else {
            Write-Warning "Robocopy completed with exit code $($process.ExitCode)"
            return $null
        }
    }
    catch {
        Write-Warning "Error during copy process: $_"
        return $null
    }
}

# Map destination drive
Write-Host "Mapping destination directory..." -ForegroundColor Cyan
$destinationMapped = Map-NetworkDrive -Path $destinationDir -DriveLetter "X"
if (!$destinationMapped) {
    Write-Error "Failed to map destination directory. Exiting script."
    exit 1
}

# Initialize report array
$report = @()

# Loop through each user email
foreach ($userEmail in $userEmails) {
    try {
        Write-Host "`nProcessing user email: $userEmail" -ForegroundColor Yellow
        
        # Trim any leading/trailing whitespace from the email
        $userEmail = $userEmail.Trim()
        Write-Host "Searching for user in Active Directory..." -ForegroundColor Cyan

        # Get the user's information from Active Directory
        $adUser = Get-ADUser -Filter "EmailAddress -eq '$userEmail'" -Properties DisplayName, homeDirectory
        
        if ($adUser) {
            $userFullName = $adUser.DisplayName
            $homeDrive = $adUser.homeDirectory
            Write-Host "Found user: $userFullName" -ForegroundColor Green
            Write-Host "Home directory: $homeDrive" -ForegroundColor Cyan

            # Map home drive
            Write-Host "Mapping home directory..." -ForegroundColor Cyan
            $homeMapped = Map-NetworkDrive -Path $homeDrive -DriveLetter "Y"
            
            if ($homeMapped) {
                $folderSize = Get-FolderSize -Path "Y:"
                if ($folderSize -gt 0) {
                    Write-Host "Home directory size: $folderSize GB" -ForegroundColor Cyan
                }

                # Sanitize the user's full name to remove invalid characters for file paths
                $sanitizedUserFullName = $userFullName -replace '[\\/:*?"<>|]', '_'
                Write-Host "Sanitized folder name: $sanitizedUserFullName" -ForegroundColor Cyan

                # Create user folder in destination
                $userFolder = Join-Path -Path "X:" -ChildPath $sanitizedUserFullName
                Write-Host "Creating destination folder: $userFolder" -ForegroundColor Cyan
                
                if (!(Test-Path -Path $userFolder)) {
                    New-Item -ItemType Directory -Path $userFolder -Force | Out-Null
                    Write-Host "Created new folder for user" -ForegroundColor Green
                } else {
                    Write-Host "Folder already exists" -ForegroundColor Yellow
                }

                # Copy files
                Write-Host "Starting file copy process..." -ForegroundColor Cyan
                try {
                    $copiedFiles = Copy-WithProgress -Source "Y:" -Destination $userFolder
                    
                    if ($copiedFiles) {
                        Write-Host "Successfully copied home drive for '$userFullName'" -ForegroundColor Green
                        Write-Host "Copied $($copiedFiles.Count) items" -ForegroundColor Cyan
                        
                        # Add copied files to report
                        Write-Host "Adding copied files to report..." -ForegroundColor Cyan
                        foreach ($file in $copiedFiles) {
                            $report += [PSCustomObject]@{
                                UserEmail = $userEmail
                                Source = $file.FullName
                                Destination = Join-Path -Path $userFolder -ChildPath $file.Name
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Error during copy process for '$userFullName': $_"
                }

                # Remove home drive mapping
                Write-Host "Removing home drive mapping..." -ForegroundColor Cyan
                Remove-PSDrive -Name "Y" -Force -ErrorAction SilentlyContinue
                net use "Y:" /delete /y 2>$null
            }
            else {
                Write-Warning "Failed to map home drive for '$userFullName'"
            }
        } else {
            Write-Warning "User with email '$userEmail' not found in Active Directory"
        }
    } catch {
        Write-Error "Error processing user '$userEmail': $_"
    }
}

# Clean up destination drive mapping
Write-Host "`nCleaning up drive mappings..." -ForegroundColor Cyan
Remove-PSDrive -Name "X" -Force -ErrorAction SilentlyContinue
net use "X:" /delete /y 2>$null

# Export the report to a CSV file
$reportPath = "C:\\temp\\copy_report.csv"
Write-Host "`nExporting report to: $reportPath" -ForegroundColor Cyan
$report | Export-Csv -Path $reportPath -NoTypeInformation
Write-Host "Report saved successfully" -ForegroundColor Green

Write-Host "`nScript execution completed!" -ForegroundColor Green
