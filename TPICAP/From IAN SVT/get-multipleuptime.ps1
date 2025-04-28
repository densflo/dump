$servers = Get-Content -Path "C:\temp\audit.txt"


$CorpDCusername = "Tradeblade\inavarrete-a"
$CorpDCpass =  ConvertTo-SecureString -String "ZZ!ikwwKP803IcPPS*c" -AsPlainText -Force
$Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass


function get-uptime { 
 param( 
 $computername =$env:computername 
 ) 
 $osname = Get-WmiObject win32_operatingsystem -ComputerName $computername -ea silentlycontinue -Credential $Creds
 if($osname)
 { 
 $lastbootuptime =$osname.ConvertTodateTime($osname.LastBootUpTime) 
 $LocalDateTime =$osname.ConvertTodateTime($osname.LocalDateTime) 
 $up =$LocalDateTime - $lastbootuptime 
 $uptime ="$($up.Days) days, $($up.Hours)h, $($up.Minutes)mins" 
 $output =new-object psobject 
 $output |Add-Member noteproperty LastBootUptime $LastBootuptime 
 $output |Add-Member noteproperty ComputerName $computername 
 $output |Add-Member noteproperty uptime $uptime 
 $output | Select-Object computername,LastBootuptime,Uptime 
 } 
 else  
 { 
 $output =New-Object psobject 
 $output =new-object psobject 
 $output |Add-Member noteproperty LastBootUptime "Not Available" 
 $output |Add-Member noteproperty ComputerName $computername 
 $output |Add-Member noteproperty uptime "Not Available"  
 $output | Select-Object computername,LastBootUptime,Uptime 
 } 
 } 


foreach ($server in $servers){

get-uptime $server


}