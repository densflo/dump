# Import the PSPKI module
Import-Module PSPKI

# Define the CA Server and CA Name based on the provided output
$caServer = "LDNPINFPKI01.ad.tullib.com"
$caName = "TPICAPSubCA1"

# Define the output path for the CSV file
$outputPath = "C:\temp\cert.csv"

# Define the date range for expiring certificates (from today to one year ahead)
$dateFrom = Get-Date
$dateTo = $dateFrom.AddYears(3)

# Attempt to connect to the Certification Authority
try {
    $ca = Get-CertificationAuthority -ComputerName $caServer | Where-Object {$_.DisplayName -eq $caName}
    if (-not $ca) {
        Write-Error "Failed to connect to the Certification Authority. Please check the CA name and server."
        return
    }

    # Get the issued certificates
    $issuedCerts = $ca | Get-IssuedRequest | Where-Object {$_.NotAfter -gt $dateFrom -and $_.NotAfter -lt $dateTo} | Select-Object *

    # Check if issued certificates were retrieved
    if ($issuedCerts -and $issuedCerts.Count -gt 0) {
        # Export the certificates to a CSV file
        $issuedCerts | Export-Csv -Path $outputPath -NoTypeInformation
        Write-Host "Export completed to $outputPath"
    } else {
        Write-Host "No certificates expiring within one year were found."
    }
} catch {
    Write-Error "An error occurred: $_"
}
