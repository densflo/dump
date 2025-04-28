$EmailFrom = "dennisjeffrey.flores@tpicap.com"
$EmailTo = "servicenow@tpicap.com"
$EmailCC = "dennisjeffrey.flores@tpicap.com"
$SMTPServer = "smtprelay.corp.ad.tullib.com" # Updated SMTP relay server FQDN
$SMTPPort = 25 # Replace with your SMTP relay server port

$servers = Get-Content "C:\temp\servers.txt"
$serverList = ($servers | ForEach-Object { "- $_`n" }) -join ""

$Subject = "Server Patching issue"
$Body = @"
IT System: Wintel Infrastructure - AM Prod
Region: EMEA
Countries Impacted: London
Assignment_Group: Global Wintel Server Support

The following servers have issues with patching:${serverList}

Please review the machine group and its deployment shavlik servers.
Please check if the the Port os open
TCP ports 137 - 139 or port 445
Please confirm if the credetials are intact
"@

$Message = New-Object System.Net.Mail.MailMessage
$Message.From = $EmailFrom
$Message.To.Add($EmailTo)
$Message.CC.Add($EmailCC)
$Message.Subject = $Subject
$Message.Body = $Body

$SMTPClient = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
$SMTPClient.Send($Message)

Write-Host "Email sent for the server list."
