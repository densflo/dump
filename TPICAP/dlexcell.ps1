# Required modules
Import-Module ExchangeOnlineManagement
Import-Module ImportExcel
Import-Module Microsoft.Identity.Client

# Function to connect to Exchange Online
function Connect-EXO {
    $clientId = "a0c73c16-a7e3-4564-9a95-2bdf47383716"
    $authority = "https://login.microsoftonline.com/common"
    $redirectUri = "http://localhost"
    $scopes = "https://outlook.office365.com/.default"
    $UserPrincipalName = "<YourUPN>"

    $publicClientApp = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($clientId).WithAuthority($authority).WithRedirectUri($redirectUri).Build()


    $authenticationResult = $publicClientApp.AcquireTokenInteractive($scopes).WithLoginHint($UserPrincipalName).Execute()



    $AccessToken = $authenticationResult.AccessToken
    Connect-ExchangeOnline -AccessToken $AccessToken
}

# Connect to Exchange Online and On-Premises
Connect-EXO
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://<YourExchangeServerFQDN>/PowerShell/ -Authentication Kerberos
Import-PSSession $Session

# Input file path and sheet names
$InputFile = "C:\temp\input.xlsx"
$SheetNames = @("productsupport-london@liquidnet", "productsupport-global@liquidnet", "productsupport@liquidnet.com")

# Function to get SMTP addresses from Distribution List
function Get-DLSMTPAddresses {
    param ([string]$DL)
    (Get-DistributionGroup -Identity $DL -ErrorAction SilentlyContinue).EmailAddresses |
    Where-Object { $_.PrefixString -eq 'smtp' } | ForEach-Object { $_.SmtpAddress }
}

# Process each sheet
foreach ($SheetName in $SheetNames) {
    $SheetData = Import-Excel -Path $InputFile -WorksheetName $SheetName

    $UpdatedData = $SheetData | ForEach-Object {
        [PSCustomObject]@{
            'Column A' = $_.'Column A'
            'Column B' = $_.'Column B'
            'Column C' = (Get-DLSMTPAddresses -DL $_.'Column A') -join ";"
        }
    }

    $UpdatedData | Export-Excel -Path $InputFile -WorksheetName $SheetName -ClearSheet -AutoSize -Force
}

# Cleanup
Remove-PSSession $Session
Disconnect-ExchangeOnline
