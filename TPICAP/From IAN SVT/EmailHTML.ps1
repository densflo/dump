$date = get-date -format "yyyy-MM-dd HHmm"

$tablenameCSV = Get-ChildItem -Path 'D:\bulk\new' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }

$corpDCtitle = $tablenameCSV -replace '.*\\' -replace ",.*"

$htmlformat  = '<title>Corp DC Replication</title>'
$htmlformat += '<style type="text/css">'
$htmlformat += 'BODY{background-color:#FFFFFF;color:#404040;font-family:Arial Narrow,sans-serif;font-size:17px;}'
$htmlformat += 'TABLE{border-width: 3px;border-style: solid;border-color: black;border-collapse: collapse;}'
$htmlformat += 'TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += 'TD{border-width: 1px;padding: 8px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += '</style>'
$bodyformat = "<h1>Corp DC Alerts $date</h1>
                <p>This Alert is automatically being generated on a daily basis.</p>
                <p>Please Investigate the fallowing DC below.</p>
                <p>Table has been created from $corpDCtitle </p>
                
                "
$postcontent = "<br>
                <br>
                <br>
                SVT Automation"




                
import-Csv -delimiter ',' -Path $tablenameCSV  | ConvertTo-Html -Head $htmlformat -Body $bodyformat -PostContent $postcontent  | Out-File "D:\bulk\new\corphtml\csv_html_test$date.html"

$tablenameHTML = Get-ChildItem -Path 'D:\bulk\new\corphtml' -Recurse  | where {$_.Extension -eq ".html"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }

#Configuration Variables for E-mail
$SmtpServer = "smtprelay.corp.ad.tullib.com" 
$EmailFrom = "SVT Automation <svtautomation@tpicap.com>"
$EmailTo = "ian.navarrete-cti@tpicap.com"
$EmailSubject = "DC Replication - Daily Report on: "+$date



$body = Get-Content -Path $tablenameHTML -Raw

Send-MailMessage -To $EmailTo -From $EmailFrom -Subject $EmailSubject -Body $body  -BodyAsHtml -SmtpServer $SmtpServer