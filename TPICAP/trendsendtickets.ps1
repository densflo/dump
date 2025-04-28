$EmailFrom = "yhamarsha@liquidnet.com"
$EmailTo = "servicenow@tpicap.com"
$EmailCC = "dennisjeffrey.flores@tpicap.com"
$SMTPServer = "smtprelay.corp.ad.tullib.com" # Updated SMTP relay server FQDN
$SMTPPort = 25 # Replace with your SMTP relay server port

$servers = Get-Content "C:\temp\servers.txt"

foreach ($server in $servers) {
    $Subject = "TrendMicro Workload Security Issue for server: $server"
    $Body = @"
IT System: Wintel Infrastructure - AM Prod
Region: EMEA
Countries Impacted: London
Assignment_Group: Global Wintel Server Support

server: $server is not communicating to the trend console, this server is unreachable inside TPICAP, please locate the server and troubleshoot the trend client by following this troubleshooting link:
https://wiki.tpicapcloud.com/display/WOD/TrendMicro+Cloud+Workload+Troubleshooting?moved=true . If the server is decomisioned, please check with DeviceD2 or servicenow for the decom ticket.
We need to offer evidence that this endpoint, without protection, is not a risk.

"@

    $Message = New-Object System.Net.Mail.MailMessage
    $Message.From = $EmailFrom
    $Message.To.Add($EmailTo)
    $Message.CC.Add($EmailCC)
    $Message.Subject = $Subject
    $Message.Body = $Body

    $SMTPClient = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
    $SMTPClient.Send($Message)

    Write-Host "Email sent for server: $server"

    Start-Sleep -Seconds 10
}
