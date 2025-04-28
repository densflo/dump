# Connect to Exchange Online
$UserPrincipalName = "-a account here that has access to exchange admin"
Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowProgress $true

# Import the list of distribution group names from the text file
$DLNames = Get-Content "C:\temp\dlinput.txt"

# Create an empty array to store the output
$Output = @()

# Loop through each distribution group name
foreach ($DLName in $DLNames) {
    # Get the distribution group details
    $DL = Get-DistributionGroup -Identity $DLName -ErrorAction SilentlyContinue

    if ($DL) {
        # Get the distribution group members
        $Members = Get-DistributionGroupMember -Identity $DLName

        # Create a custom object to store the group name, SMTP address, and members
        $Result = New-Object PSObject -Property @{
            GroupName   = $DL.Name
            SMTPAddress = $DL.PrimarySmtpAddress
            Members     = ($Members | ForEach-Object { $_.PrimarySmtpAddress }) -join ", "
        }

        # Add the custom object to the output array
        $Output += $Result
    } else {
        Write-Warning "Distribution group $DLName not found."
    }
}

# Export the output array to a CSV file
$Output | Export-Csv -Path "C:\temp\DistributionGroupDetails.csv" -NoTypeInformation

# Disconnect from Exchange Online
Disconnect-ExchangeOnline -Confirm:$false
