[string]$vcenter = "SNG2VA0001"
$date = get-date -format "MM-dd-yyyy"
New-Item "D:\Vmware\Snapshot\$vcenter-Snapshot-$date" -ItemType Directory
$latestfolderlocation = "D:\Vmware\Snapshot\$vcenter-Snapshot-$date"


 Connect-VIServer -Server $vcenter -Username "corp\srvcDev42VC" -Password "R#2TwaM@"

                                                            
     
                                                            $vms = get-vm -Server $vcenter

                                                             foreach ($vm in $vms){
                                    
                                                            $vmsnap = Get-Snapshot -vm $vm  | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 
                                                            

$nameitem = $vmsnap.vm

$htmlformat  = '<title>$vcenter Snapshot deletion ticket Request</title>'
$htmlformat += '<style type="text/css">'
$htmlformat += 'BODY{background-color:#FFFFFF;color:#404040;font-family:Arial Narrow,sans-serif;font-size:17px;}'
$htmlformat += 'TABLE{border-width: 3px;border-style: solid;border-color: black;border-collapse: collapse;}'
$htmlformat += 'TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += 'TD{border-width: 1px;padding: 8px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += '</style>'
$bodyformat = "<h1>Snapshot deletion request for $nameitem $date</h1>
                <p>This Alert is automatically being generated on a weekly basis.</p>
                <p>IT System: Vmware ESX - AP Prod<br>
                   Region: APAC<br>
                   Countries Impacted: Singapore<br>
                   Assignment_Group: Global Wintel Server Support</p>
                <p>Please delete the fallowing snapshot below.</p>
                <p>you can find the snapshot in $vcenter</p>
                
                "
$postcontent = "<br>
                <br>
                SVT Automation"


$vmsnap| ConvertTo-Html -Head $htmlformat -Body $bodyformat -PostContent $postcontent | Out-File "$latestfolderlocation\$nameitem.htm"


 


 }


$htmls = Get-ChildItem -Path $latestfolderlocation -Name


foreach($html in $htmls){

$body = Get-Content -Path "$latestfolderlocation\$html" -Raw

#Configuration Variables for E-mail
$SmtpServer = "smtprelay.corp.ad.tullib.com" 
$EmailFrom = "SVT Automation <svtautomation@tpicap.com>"
$EmailTo = "globalservicedesk@tpicap.com"
$CC = "wintel.operations@tpicap.com"
$EmailSubject = "Snapshot Deletion $html : "+$date


Send-MailMessage -To $EmailTo -Cc $CC -From $EmailFrom -Subject $EmailSubject -Body $body  -BodyAsHtml -SmtpServer $SmtpServer

}