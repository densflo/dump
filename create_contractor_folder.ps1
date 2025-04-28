# Create contractor folder based on home drive
param (
    [string]$UserEmail,
    [string]$InputFile
)

# Destination directory
$destinationDir = "\\ldnfs1.eur.ad.tullib.com\serverSupp$\contractor"
Write-Host "Destination directory set to: $destinationDir" -ForegroundColor Cyan

# Validate parameters
if (-not $UserEmail -and -not $InputFile) {
    Write-Host "Either UserEmail or InputFile parameter is required" -ForegroundColor Red
    exit 1
}

if ($InputFile -and -not (Test-Path $InputFile)) {
    Write-Host "Input file not found: $InputFile" -ForegroundColor Red
    exit 1
}

# Function to process a single email
function Process-UserEmail {
    param (
        [string]$Email
    )
    
    try {
        Write-Host "Processing user email: $Email" -ForegroundColor Yellow
        
        # Trim any leading/trailing whitespace from the email
        $Email = $Email.Trim()
        Write-Host "Searching for user in Active Directory..." -ForegroundColor Cyan

        # Get the user's information from Active Directory
        $adUser = Get-ADUser -Filter "EmailAddress -eq '$Email'" -Properties DisplayName, homeDirectory
        
        if ($adUser) {
            $userFullName = $adUser.DisplayName
            $homeDrive = $adUser.homeDirectory
            Write-Host "Found user: $userFullName" -ForegroundColor Green
            Write-Host "Home directory: $homeDrive" -ForegroundColor Cyan

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
        } else {
            Write-Warning "User with email '$Email' not found in Active Directory"
            return $false
        }
    } catch {
        Write-Error "Error processing user '$Email': $_"
        return $false
    }
    return $true
}

# Function to map network drive
function Map-NetworkDrive {
    param (
        [string]$Path,
        [string]$DriveLetter
    )
    try {
        # Remove existing mapping if it exists
        if (Test-Path ($DriveLetter + ":")) {
            Write-Host ("Removing existing mapping for " + $DriveLetter + ":") -ForegroundColor Cyan
            Remove-PSDrive -Name $DriveLetter -Force -ErrorAction SilentlyContinue
            net use ($DriveLetter + ":") /delete /y 2>$null
        }
        
        Write-Host "Mapping $Path to $DriveLetter" -ForegroundColor Cyan
        $drivePath = $DriveLetter + ":" 
        $result = net use $drivePath "$Path" /PERSISTENT:NO
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully mapped drive $DriveLetter" -ForegroundColor Green
            return $true
        } else {
        Write-Warning ("Failed to map drive " + $DriveLetter + ". Error: " + $result)
            return $false
        }
    }
    catch {
        Write-Warning ("Error mapping drive " + $DriveLetter + ": " + $_)
        return $false
    }
}

# Map destination drive
Write-Host "Mapping destination directory..." -ForegroundColor Cyan
$destinationMapped = Map-NetworkDrive -Path $destinationDir -DriveLetter "X"
if (!$destinationMapped) {
    Write-Error "Failed to map destination directory. Exiting script."
    exit 1
}

try {
    if ($InputFile) {
        # Process batch from input file
        Write-Host "Processing emails from file: $InputFile" -ForegroundColor Cyan
        $emails = Get-Content -Path $InputFile
        $total = $emails.Count
        $processed = 0
        $successCount = 0
        
        foreach ($email in $emails) {
            $processed++
            Write-Host "Processing email $processed of $total: $email" -ForegroundColor Yellow
            if (Process-UserEmail -Email $email) {
                $successCount++
            }
        }
        
        Write-Host "Batch processing completed: $successCount of $total processed successfully" -ForegroundColor Green
    } else {
        # Process single email
        Write-Host "Processing user email: $UserEmail" -ForegroundColor Yellow
        Process-UserEmail -Email $UserEmail
    }
} catch {
    Write-Error "Error during processing: $_"
    exit 1
} finally {
    # Clean up destination drive mapping
    Write-Host "Cleaning up drive mappings..." -ForegroundColor Cyan
    Remove-PSDrive -Name "X" -Force -ErrorAction SilentlyContinue
    net use "X:" /delete /y 2>$null
}

Write-Host "Script execution completed!" -ForegroundColor Green
