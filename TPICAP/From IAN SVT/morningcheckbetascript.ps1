[string]$vcenter = "LD5PINFVCA01"
$date = get-date -format "MM-dd-yyyy"


$latestfolderlocation = "D:\Vmware\Snapshot\$vcenter-Snapshot-$date"

if(!(Test-Path -PathType Container $latestfolderlocation)){

New-Item $latestfolderlocation -ItemType Directory

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
                <p>IT System: Vmware ESX - AM Prod<br>
                   Region: AMER<br>
                   Countries Impacted: united states of america<br>
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
$EmailTo = "ian.navarrete-cti@tpicap.com"
$EmailSubject = "Snapshot Deletion $html : "+$date


Send-MailMessage -To $EmailTo -From $EmailFrom -Subject $EmailSubject -Body $body  -BodyAsHtml -SmtpServer $SmtpServer

}


}else{

New-Item "$latestfolderlocation\Temp" -ItemType Directory

$compare = Get-ChildItem -Path $latestfolderlocation -Name

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
                <p>IT System: Vmware ESX - AM Prod<br>
                   Region: AMER<br>
                   Countries Impacted: united states of america<br>
                   Assignment_Group: Global Wintel Server Support</p>
                <p>Please delete the fallowing snapshot below.</p>
                <p>you can find the snapshot in $vcenter</p>
                
                "
$postcontent = "<br>
                <br>
                SVT Automation"

if(Compare-Object $compare "$nameitem.htm" | Where-Object{$_.sideindicator -eq "=>"} |select *  ){

$vmsnap | ConvertTo-Html -Head $htmlformat -Body $bodyformat -PostContent $postcontent | Out-File "$latestfolderlocation\temp\$nameitem.htm"

$htmlstemp = Get-ChildItem -Path "$latestfolderlocation\temp" -Name


foreach($html in $htmlstemp){

$body = Get-Content -Path "$latestfolderlocation\temp\$html" -Raw

#Configuration Variables for E-mail
$SmtpServer = "smtprelay.corp.ad.tullib.com" 
$EmailFrom = "SVT Automation <svtautomation@tpicap.com>"
$EmailTo = "ian.navarrete-cti@tpicap.com"
$EmailSubject = "Snapshot Deletion $html : "+$date


Send-MailMessage -To $EmailTo  -From $EmailFrom -Subject $EmailSubject -Body $body  -BodyAsHtml -SmtpServer $SmtpServer

Move-Item -Path "$latestfolderlocation\temp\$htmlstemp" -Destination $latestfolderlocation

         }

      }
 


  }

}




 

                                                            
     


 Disconnect-VIServer -Server $vcenter -Force -Confirm

