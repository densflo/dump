[string]$vcenter = "syd2va0001"
$date = get-date -format "MM-dd-yyyy"
$date2 = get-date -format "MM-dd-yyyy HH:ss"
$latestfolderlocation = "\\10.90.80.243\Vmware\VcenterAlerts\$vcenter"
$Itemsnumber = (Get-ChildItem -Path $latestfolderlocation -Directory | Measure-Object).Count


$latestfolder =  Get-ChildItem -Path $latestfolderlocation -Attributes directory | Sort-Object 'creationtime' -Descending |Select-Object -First 1 
$latestfoldername = $latestfolder.name
$folderAge = Get-ChildItem -Path "$latestfolderlocation" -Attributes directory | where {$_.name -eq "$latestfoldername"}
$Todaysdate = (get-date)


if($Itemsnumber -eq '0'){

Write-host "option 1"

New-Item "$latestfolderlocation\$vcenter-Alerts-$date" -ItemType Directory

                                                           
Connect-VIServer -Server $vcenter -Username "corp\srvcDev42VC" -Password "R#2TwaM@"

Function Get-TriggeredAlarms {
  	                       param (
  		                    $vCenter = $(throw "A vCenter must be specified.")
  	                          )

                            
  		                       $vc =  $vCenter
  	                        

                            
  	                        $rootFolder = Get-Folder -Server $vc "Datacenters"

                            foreach ($ta in $rootFolder.ExtensionData.TriggeredAlarmState) {
  		                            $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  		                            $alarm.VC = $vCenter
  		                            $alarm.Alarm = (Get-View -Server $vc $ta.Alarm).Info.Name
  		                            $entity = Get-View -Server $vc $ta.Entity
  		                            $alarm.Entity = (Get-View -Server $vc $ta.Entity).Name
  		                            $alarm.EntityType = (Get-View -Server $vc $ta.Entity).GetType().Name
  		                            $alarm.Status = [string]$ta.OverallStatus 
  		                            $alarm.Time = $ta.Time 
  		                            $alarm.Acknowledged = $ta.Acknowledged
  		                            $alarm.AckBy = $ta.AcknowledgedByUser
  		                            $alarm.AckTime = $ta.AcknowledgedTime
  		                            $alarm
  	                                 }
  	
                                    }

                         $alarms += Get-TriggeredAlarms $vCenter | Where-Object {$_.Acknowledged -inotmatch 'True'}         
                         
foreach($alarm in $alarms){


$nameitem = $alarm.Entity

$htmlformat  = '<title>$vcenter Alert!!! </title>'
$htmlformat += '<style type="text/css">'
$htmlformat += 'BODY{background-color:#FFFFFF;color:#404040;font-family:Arial Narrow,sans-serif;font-size:17px;}'
$htmlformat += 'TABLE{border-width: 3px;border-style: solid;border-color: black;border-collapse: collapse;}'
$htmlformat += 'TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += 'TD{border-width: 1px;padding: 8px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += '</style>'
$bodyformat = "<h1>Alert Detected for $nameitem $date2 UK Time</h1>
                <p>IT System: Vmware ESX - AP Prod<br>
                   Region: APAC<br>
                   Countries Impacted: Australia<br>
                   Assignment_Group: Global Wintel Server Support</p>
                <p>Please investigate the alert.</p>
                
                
                "
$postcontent = "<br>
                <br>
                SVT Automation"


$alarm | ConvertTo-Html -Head $htmlformat -Body $bodyformat -PostContent $postcontent | Out-File "$latestfolderlocation\$vcenter-Alerts-$date\$nameitem.htm"


}   

$htmls = Get-ChildItem -Path "$latestfolderlocation\$vcenter-Alerts-$date" -Name


foreach($html in $htmls){

$body = Get-Content -Path "$latestfolderlocation\$vcenter-Alerts-$date\$html" -Raw

#Configuration Variables for E-mail
$SmtpServer = "smtprelay.corp.ad.tullib.com" 
$EmailFrom = "SVT Automation <svtautomation@tpicap.com>"
$EmailTo = "ian.navarrete-cti@tpicap.com"
$EmailSubject = "$vcenter Alert!!! $html : "+$date2


Send-MailMessage -To $EmailTo -From $EmailFrom -Subject $EmailSubject -Body $body  -BodyAsHtml -SmtpServer $SmtpServer


}


}elseif(($folderAge.creationtime).AddDays(7) -le $Todaysdate){

Write-host "option 2"
New-Item $latestfolderlocation\$vcenter-Alerts-$date -ItemType Directory

Connect-VIServer -Server $vcenter -Username "corp\srvcDev42VC" -Password "R#2TwaM@"

                                                           

Function Get-TriggeredAlarms {
  	                       param (
  		                    $vCenter = $(throw "A vCenter must be specified.")
  	                          )

                            
  		                       $vc =  $vCenter
  	                        

                            
  	                        $rootFolder = Get-Folder -Server $vc "Datacenters"

                            foreach ($ta in $rootFolder.ExtensionData.TriggeredAlarmState) {
  		                            $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  		                            $alarm.VC = $vCenter
  		                            $alarm.Alarm = (Get-View -Server $vc $ta.Alarm).Info.Name
  		                            $entity = Get-View -Server $vc $ta.Entity
  		                            $alarm.Entity = (Get-View -Server $vc $ta.Entity).Name
  		                            $alarm.EntityType = (Get-View -Server $vc $ta.Entity).GetType().Name
  		                            $alarm.Status = [string]$ta.OverallStatus 
  		                            $alarm.Time = $ta.Time 
  		                            $alarm.Acknowledged = $ta.Acknowledged
  		                            $alarm.AckBy = $ta.AcknowledgedByUser
  		                            $alarm.AckTime = $ta.AcknowledgedTime
  		                            $alarm
  	                                 }
  	
                                    }

                         $alarms = Get-TriggeredAlarms $vCenter | Where-Object {$_.Acknowledged -inotmatch 'True'}          
                         
foreach($alarm in $alarms){


$nameitem = $alarm.Entity

$htmlformat  = '<title>$vcenter Alert!!! </title>'
$htmlformat += '<style type="text/css">'
$htmlformat += 'BODY{background-color:#FFFFFF;color:#404040;font-family:Arial Narrow,sans-serif;font-size:17px;}'
$htmlformat += 'TABLE{border-width: 3px;border-style: solid;border-color: black;border-collapse: collapse;}'
$htmlformat += 'TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += 'TD{border-width: 1px;padding: 8px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += '</style>'
$bodyformat = "<h1>Alert Detected for $nameitem $date2 UK Time</h1>
                <p>IT System: Vmware ESX - AP Prod<br>
                   Region: APAC<br>
                   Countries Impacted: Australia<br>
                   Assignment_Group: Global Wintel Server Support</p>
                <p>Please investigate the alert.</p>
                
                
                "
$postcontent = "<br>
                <br>
                SVT Automation"


$alarm | ConvertTo-Html -Head $htmlformat -Body $bodyformat -PostContent $postcontent | Out-File "$latestfolderlocation\$vcenter-Alerts-$date\$nameitem.htm"


}   

$htmls = Get-ChildItem -Path "$latestfolderlocation\$vcenter-Alerts-$date" -Name


foreach($html in $htmls){

$body = Get-Content -Path "$latestfolderlocation\$vcenter-Alerts-$date\$html" -Raw

#Configuration Variables for E-mail
$SmtpServer = "smtprelay.corp.ad.tullib.com" 
$EmailFrom = "SVT Automation <svtautomation@tpicap.com>"
$EmailTo = "ian.navarrete-cti@tpicap.com"
$EmailSubject = "$vcenter Alert!!! $html : "+$date2


Send-MailMessage -To $EmailTo -From $EmailFrom -Subject $EmailSubject -Body $body  -BodyAsHtml -SmtpServer $SmtpServer


}




}else{

Write-host "option 3"

New-Item "$latestfolderlocation\$vcenter-Alerts-$date\temp" -ItemType Directory -ErrorAction SilentlyContinue
$compare = Get-ChildItem -Path "$latestfolderlocation\$vcenter-Alerts-$date" -Name

                                                          
Connect-VIServer -Server $vcenter -Username "corp\srvcDev42VC" -Password "R#2TwaM@"

Function Get-TriggeredAlarms {
  	                       param (
  		                    $vCenter = $(throw "A vCenter must be specified.")
  	                          )

                            
  		                       $vc =  $vCenter
  	                        

                            
  	                        $rootFolder = Get-Folder -Server $vc "Datacenters"

                            foreach ($ta in $rootFolder.ExtensionData.TriggeredAlarmState) {
  		                            $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  		                            $alarm.VC = $vCenter
  		                            $alarm.Alarm = (Get-View -Server $vc $ta.Alarm).Info.Name
  		                            $entity = Get-View -Server $vc $ta.Entity
  		                            $alarm.Entity = (Get-View -Server $vc $ta.Entity).Name
  		                            $alarm.EntityType = (Get-View -Server $vc $ta.Entity).GetType().Name
  		                            $alarm.Status = [string]$ta.OverallStatus 
  		                            $alarm.Time = $ta.Time 
  		                            $alarm.Acknowledged = $ta.Acknowledged
  		                            $alarm.AckBy = $ta.AcknowledgedByUser
  		                            $alarm.AckTime = $ta.AcknowledgedTime
  		                            $alarm
  	                                 }
  	
                                    }

                                    
                               	                         
  	                         $alarms = Get-TriggeredAlarms $vCenter | Where-Object {$_.Acknowledged -inotmatch 'True'}
foreach($alarm in $alarms){


$nameitem = $alarm.Entity

$htmlformat  = '<title>$vcenter Alert!!! </title>'
$htmlformat += '<style type="text/css">'
$htmlformat += 'BODY{background-color:#FFFFFF;color:#404040;font-family:Arial Narrow,sans-serif;font-size:17px;}'
$htmlformat += 'TABLE{border-width: 3px;border-style: solid;border-color: black;border-collapse: collapse;}'
$htmlformat += 'TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += 'TD{border-width: 1px;padding: 8px;border-style: solid;border-color: black;background-color:#f8f8f8}'
$htmlformat += '</style>'
$bodyformat = "<h1>Alert Detected for $nameitem $date2 UK Time</h1>
                <p>IT System: Vmware ESX - AP Prod<br>
                   Region: APAC<br>
                   Countries Impacted: Australia<br>
                   Assignment_Group: Global Wintel Server Support</p>
                <p>Please investigate the alert.</p>
                
                
                "
$postcontent = "<br>
                <br>
                SVT Automation"


if(Compare-Object $compare "$nameitem.htm" | Where-Object{$_.sideindicator -eq "=>"} |select *  ){
$alarm | ConvertTo-Html -Head $htmlformat -Body $bodyformat -PostContent $postcontent | Out-File "$latestfolderlocation\$vcenter-Alerts-$date\temp\$nameitem.htm"
$htmlstemp = Get-ChildItem -Path "$latestfolderlocation\$vcenter-Alerts-$date\temp" -Name


foreach($html in $htmlstemp){

$body = Get-Content -Path "$latestfolderlocation\$vcenter-Alerts-$date\temp\$html" -Raw

#Configuration Variables for E-mail
$SmtpServer = "smtprelay.corp.ad.tullib.com" 
$EmailFrom = "SVT Automation <svtautomation@tpicap.com>"
$EmailTo = "ian.navarrete-cti@tpicap.com"
$EmailSubject = "$vcenter Alert!!! $html : "+$date2


Send-MailMessage -To $EmailTo  -From $EmailFrom -Subject $EmailSubject -Body $body  -BodyAsHtml -SmtpServer $SmtpServer


 

}   


         }

Move-Item -Path "$latestfolderlocation\$vcenter-Alerts-$date\temp\*" -Destination "$latestfolderlocation\$vcenter-Alerts-$date"


      }

}



 Clear-Variable -Name alarm -Force
 Clear-Variable -Name alarms -Force