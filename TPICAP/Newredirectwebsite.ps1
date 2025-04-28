# Define the website name and redirection URL
$websiteName = "jira.na.ad.tullib.com"
$redirectionUrl = "https://jira.tpicapcloud.com"

# Define the website root directory
$websiteRoot = "C:\inetpub\wwwroot\$websiteName"

# Check the bindings of the default website and modify them if necessary
$defaultBindings = Get-WebBinding -Name "Default Web Site"
if ($defaultBindings.protocol -eq "http" -and $defaultBindings.bindingInformation -eq "*:80:") {
    Set-WebBinding -Name "Default Web Site" -BindingInformation "*:8080:" -PropertyName Port
}

# Create the website root directory if it doesn't exist
if (!(Test-Path $websiteRoot)) {
    New-Item $websiteRoot -Type Directory
}

# Create a default document for the website
$defaultDocument = "index.html"
$defaultContent = "<html><head><title>Welcome to $websiteName</title></head><body><h1>Welcome to $websiteName</h1><p>This is the default document for $websiteName</p></body></html>"
Set-Content -Path "$websiteRoot\$defaultDocument" -Value $defaultContent

# Create the website in IIS
New-WebSite -Name $websiteName -PhysicalPath $websiteRoot -Port 80 -HostHeader $websiteName -Force
$thumbprint = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "jira.na.ad.tullib.com" } | Select-Object -First 1).Thumbprint
$binding = Get-WebBinding -Name $websiteName -Port 443
$binding.Protocol = "https"
$binding.CertificateHash = $thumbprint
Set-WebBinding -InputObject $binding

# Set up the HTTP redirection for the website
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "enabled" -Value "True"
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "destination" -Value $redirectionUrl
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "exactDestination" -Value "True"
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "httpResponseStatus" -Value "Permanent"
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "childOnly" -Value "False"

# Set up the HTTPS redirection for the website
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "enabled" -Value "True" -Location "https://$websiteName"
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "destination" -Value $redirectionUrl -Location "https://$websiteName"
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "exactDestination" -Value "True" -Location "https://$websiteName"
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "httpResponseStatus" -Value "Permanent" -Location "https://$websiteName"
Set-WebConfigurationProperty -Filter "/system.webServer/httpRedirect" -PSPath "IIS:\Sites\$websiteName" -Name "childOnly" -Value "False" -Location "https://$websiteName"
