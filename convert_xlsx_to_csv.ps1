# Install the ImportExcel module if it's not already installed
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Install-Package -Name ImportExcel -Scope CurrentUser -Force
}

# Import the ImportExcel module
Import-Module ImportExcel

# Path to the input XLSX file
$xlsxPath = "C:\Users\d_flores\OneDrive - TP ICAP\Documents\Code\ExportSchedule_2025-01-01 to 2025-03-02 TEAM_4fd310a2-d723-4ad9-afcb-8ce7d291e4bf.xlsx"

# Path to the output CSV file
$csvPath = "C:\Users\d_flores\OneDrive - TP ICAP\Documents\Code\users.csv"

# Convert the XLSX to CSV
try {
    $data = Import-Excel -Path $xlsxPath
    $data | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Successfully converted '$xlsxPath' to '$csvPath'"
} catch {
    Write-Error "Error converting XLSX to CSV: $_"
}
