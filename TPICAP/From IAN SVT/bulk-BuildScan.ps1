$username = $null
$CorpDCpass = $null
$CorpCreds = $null
$servers = $null
$servers = Get-Content -Path "C:\temp\appd.txt"
#$ErrorActionPreference= 'silentlycontinue'
$ping=$null

$final = foreach($servername in $servers){

       $FQDNfinal = $servername.Split( "." )[1]
       switch ($FQDNfinal){
           "corp" {
                 $username = "corp.ad.tullib.com\CORP PMS"
                 $CorpDCpass =  ConvertTo-SecureString -String 'oPiPTvluz2D*3VxOD$Nhlc6lS5q$AMvH' -AsPlainText -Force}
               
            "na" {
                 $username = "na.ad.tullib.com\NA PMS"
                 $CorpDCpass =  ConvertTo-SecureString -String '#d4RRAmT$lyprF)Tl&!bQ#WDqTXQTXgE' -AsPlainText -Force}
               
             "us"{
                 $username = "us.icap.com\US PMS"
                 $CorpDCpass =  ConvertTo-SecureString -String 'JGkiIzX4uFzuR*wXosbO*U16NV^5JO6B' -AsPlainText -Force}
               
            "global"{
                 $username = "GLOBAL PMS\GBL DA 4"
                 $CorpDCpass =  ConvertTo-SecureString -String 'a6P!qTIndu)$kJCga' -AsPlainText -Force}
                 
             "lnholdings"{
                 $username = "lnholdings.com\LN PMS"
                 $CorpDCpass =  ConvertTo-SecureString -String 'iNHWBKF2D&WpudU' -AsPlainText -Force}
   
             "ad"   {
                 $username = "ad.tullib.com\RT TPICAP PMS"
                 $CorpDCpass =  ConvertTo-SecureString -String 'XCQ4d@cvJ5EXq@wBktdbXx^mf)ZvWhBX' -AsPlainText -Force}
   
              "icap"{
                  $username = "icap.com\RT ICAP PMS"
                  $CorpDCpass =  ConvertTo-SecureString -String 'k5@lBIC9fAVQOjX$Kd(Ex33ApNJf1KAz' -AsPlainText -Force}
          }
   $CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$CorpDCpass

if(Test-WSMan -ComputerName $servername -Credential $CorpCreds -Authentication Kerberos){

$session = New-CimSession -ComputerName $ServerName -Credential $CorpCreds

$Qualys  = if(Get-WmiObject -Class Win32_Product -ComputerName $servername -Credential $CorpCreds | where vendor -eq "Qualys, Inc.")    {Write-Output 'Installed'}else{Write-Output 'Not Present'}
$appd    = if(Get-WmiObject -Class Win32_Product -ComputerName $servername -Credential $CorpCreds | where vendor -eq "AppDynamics")     {Write-Output 'Installed'}else{Write-Output 'Not Present'}
$CheckMK = if(Get-WmiObject -Class Win32_Product -ComputerName $servername -Credential $CorpCreds | where vendor -eq "tribe29 GmbH")    {Write-Output 'Installed'}else{Write-Output 'Not Present'}
$CrowdStrike = if(Get-WmiObject -Class Win32_Product -ComputerName $servername -Credential $CorpCreds | where vendor -eq "CSSensor")    {Write-Output 'Installed'}else{Write-Output 'Not Present'}
$Secops = if(Get-WmiObject -Class Win32_Product -ComputerName $servername -Credential $CorpCreds | where vendor -eq "Specops Softwarer")    {Write-Output 'Installed'}else{Write-Output 'Not Present'}
$Elastic = if(Get-WMIObject -Query "select * from win32_service where name='Elastic Agent'" -computer $ServerName -Credential $CorpCreds | Where-Object State  -EQ 'running') {
                  
                  Write-Output 'running'

                         }elseif(Get-WMIObject -Query "select * from win32_service where name='Elastic Agent'" -computer $ServerName -Credential $CorpCreds  | Where-Object State  -EQ 'Stopped'){
                         
                  Write-Output 'Not Running'
                         }else{
                         
                  Write-Output 'Not installed'  
                         }

$trend = Get-WmiObject -Class Win32_Product -ComputerName $servername -Credential $CorpCreds | where vendor -eq "Trend Micro Inc."
$trendFinal = if($trend){
$trend.name
}else{
Write-Output 'not installed'
}


$SmbCheck = get-SmbServerConfiguration -CimSession $session   | select 'EnableSMB1Protocol' -ExpandProperty EnableSMB1Protocol
$windowsDefender = if (Get-Service Windefend -ComputerName $servername -ErrorAction SilentlyContinue  | Where-Object Status -EQ Stopped){
Write-Output Stopped
}elseif (Get-Service Windefend -ComputerName $servername  -ErrorAction SilentlyContinue | Where-Object Status -EQ Running){
Write-Output Running
}else{
Write-Output notinstalled
}


$a2rmTask = if(Get-ScheduledTask -CimSession $session -TaskName A2RM_CMDB_Update ){
Get-ScheduledTask -CimSession $session -TaskName A2RM_CMDB_Update | select state -ExpandProperty state
}else{

Write-Output 'Not Present'

}
$AppDTask = if(Get-ScheduledTask -CimSession $session -TaskName AppD_Daily_Update ){
Get-ScheduledTask -CimSession $session -TaskName AppD_Daily_Update | select state -ExpandProperty state
}else{

Write-Output 'Not Present'

}
$serverLocaladmin = if (Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-LocalGroupMember  -Group administrators | Where-Object name -Like "*LESA*"} ){

Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-LocalGroupMember  -Group administrators | Where-Object name -Like "*LESA*"} 

}else{

Write-Output 'not Present'

}
$serverSecGroupLocaladmin = if (Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-LocalGroupMember  -Group administrators  | Where-Object name -CMatch "L $servername"}){


Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-LocalGroupMember  -Group administrators  | Where-Object name -Match "L $env:COMPUTERNAME"}

}else{

Write-Output 'not Present'

}
#$Uac = Get-UACStatus -Computer $servername 
$executionpolicy = Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ExecutionPolicy}


#specter registry entry

$FeatureSettingsOverrideMask = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

}  
$FeatureSettingsOverride = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

}
$QualityCompat = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -Name cadca5fe-87d3-4b96-b7fb-a231484277cc}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

}  



#windows Update reg settings 
$WindowsUpdate = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

}  
$netlogon1 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name \\\\*\\NETLOGON}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

} 
$sysvol1 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name \\\\*\\SYSVOL}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

}
$netlogon2 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name \\*\NETLOGON}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

}
$sysvol2 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name \\*\SYSVOL}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

}

#permitted Managers SNMP
$PermittedMgr01 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' -Name 1}){  

Write-Output 'True'
    
}else{

Write-Output  'False'

}  
$PermittedMgr02 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' -Name 2}){  

Write-Output  'True'
    
}else{

Write-Output  'False'

}  
$PermittedMgr03 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' -Name 3}){  

Write-Output  'True'
    
}else{

Write-Output  'False'

}
$TrapLDNPRV321654 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration\LDNPRV321654' -Name 1,2}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

} 
$TrapLDNPUB321654 = if(Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration\LDNPUB321654' -Name 1,2}){  

Write-Output 'True'
    
}else{

Write-Output 'False'

} 

$ServerObject = Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ADComputer -Identity "$servername"}
$Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $servername -Credential $CorpCreds  -EA Stop | ? {$_.IPEnabled}
$proxy = if (Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Test-Path  "C:\Program Files (x86)\ICAP\SetProxy\BlankProxy.exe"}){Write-Output 'True'}else{Write-Output 'False'}

$remote = Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {Get-ItemProperty -Path: 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'  fDenyTSConnections}
$remotefinal = $remote.fDenyTSConnections
$RDPFinal = if ($remotefinal -eq '0'){
Write-output 'enabled'
}elseif($remotefinal -eq '1'){
write-output 'Disabled'
}else{
Write-output 'No RDP entry'
}

$powershellRemote = if(Test-WSMan -ComputerName $servername -Credential $CorpCreds -Authentication Kerberos){
Write-Output 'Enabled'
}else{
Write-Output 'Disabled'
}

$cpuspecs = Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {(Get-ComputerInfo ).CsProcessors.name[0]}
$cpucount = Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {(Get-ComputerInfo).CsNumberOfProcessors}
$OSbuildate = Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {(Get-ComputerInfo).WindowsInstallDateFromRegistry}
$domain = Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {(Get-ComputerInfo).CsDomain}
$recentpatch = Get-HotFix -ComputerName $servername -Credential $CorpCreds | Sort-Object installedon | select -First 1   
$DNSForwarders = Invoke-Command -ComputerName $servername -Credential $CorpCreds  -ScriptBlock {(get-dnsserverforwarder).IpAddress.IPaddresstoString}
  
   [PSCustomObject] @{
                                         'Server Name'   = $servername
                                         'Server Domain' = $domain
                                      'Operating System' = (Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem).Caption
                                            'CPU Specs'  = $cpuspecs 
                                      'CPU Cores Count'  = $cpucount
                                       'Physical Memory' = (Get-CimInstance -CimSession $session  -ClassName win32_computersystem).TotalPhysicalMemory / 1GB | ForEach-Object { "$([Math]::Round($_, 2)) GBs " }
                                                 'Model' = (Get-CimInstance -CimSession $session  -ClassName win32_computersystem).Model
                                          'Manufacturer' = (Get-CimInstance -CimSession $session  -ClassName win32_computersystem).Manufacturer
                                         'OS Build Date' = $OSbuildate
                                           'DNS Forwarders' = $DNSForwarders
                                       'Is RDP Enabled?' = $RDPFinal
                                'Server Object Location' = $ServerObject
                                             APPD        = $appd
                                            TrendMicro   = $trendFinal
                                            Qualys       = $Qualys
                                            CheckMk      = $CheckMK
                                   "Elastic For DC only" = $Elastic
                                   "Secops For DC only"  = $Secops
                                   "CrowStrike"       = $CrowdStrike
                                    'SMBv1 Enabled?'      = $SmbCheck
                                     #'UAC Status enabled?' = $Uac
                                  'Windows No Auto Update?'= $WindowsUpdate
                                        'Windows Defender' = $windowsDefender
                                        'A2rm Daily Task'  = $a2rmTask
                                        'AppD Daily Task'  = $AppDTask
                                        'Lesa Local Admin' = $serverLocaladmin
                       'Local admin server Security Group' = $serverSecGroupLocaladmin
                            'Powershell Remoting Enabled?' = $powershellRemote
                             'Powershell Execution Policy' = $executionpolicy
                   'specter Feature Settings OverrideMask' = $FeatureSettingsOverrideMask
                        'specter FeatureSettings Override' = $FeatureSettingsOverride
                   'specter FeatureSettings QualityCompat' = $QualityCompat
                   'Security Registry Fix entry for \\\\*\\NETLOGON' = $netlogon1 
                   'Security Registry Fix entry for \\\\*\\SYSVOL' = $sysvol1
                   'Security Registry Fix entry for \\*\NETLOGON' = $netlogon2 
                   'Security Registry Fix entry for \\*\SYSVOL' = $sysvol2
                   'SNMP Permitted Managers Entry 1' = $PermittedMgr01
                   'SNMP Permitted Managers Entry 2' = $PermittedMgr02
                   'SNMP Permitted Managers Entry 3' = $PermittedMgr03
                   'Trap Config For LDNPRV321654' = $TrapLDNPRV321654
                   'Trap Config For LDNPUB321654' = $TrapLDNPUB321654
                              'Proxy Configured?' = $proxy 
                                  'Telnet Client' = (Get-WindowsFeature -ComputerName $servername -Credential $CorpCreds -name telnet-client).Installstate
                                  'SNMP-Service' = (Get-WindowsFeature -ComputerName $servername -Credential $CorpCreds -name SNMP-Service).Installstate
                                            IPAddress = $Network.IPAddress[0]
                                            SubnetMask = $Network.IPSubnet[0]
                                           DefaultGateway = $Network.DefaultIPGateway[0]
                                           DHCPEnabled = $Network.DHCPEnabled
                                           DnsServer = $Network.DNSServerSearchOrder
                                           'Recent patch Date' = $recentpatch.installedon
                                               }

}else{
  
  [PSCustomObject] @{
                                         'Server Name'   = $servername
                                         'Server Domain' = 'Offline/Access issue'
                                      'Operating System' = 'Offline/Access issue'
                                            'CPU Specs'  = 'Offline/Access issue'
                                      'CPU Cores Count'  = 'Offline/Access issue'
                                       'Physical Memory' = 'Offline/Access issue'
                                                 'Model' = 'Offline/Access issue'
                                          'Manufacturer' = 'Offline/Access issue'
                                         'OS Build Date' = 'Offline/Access issue'
                                         'DNS Forwarders'= 'Offline/Access issue'
                                       'Is RDP Enabled?' = 'Offline/Access issue'
                                'Server Object Location' = 'Offline/Access issue'
                                             APPD        = 'Offline/Access issue'
                                            TrendMicro   = 'Offline/Access issue'
                                            Qualys       = 'Offline/Access issue'
                                            CheckMk      = 'Offline/Access issue'
                                    'SMBv1 Enabled?'      = 'Offline/Access issue'
                                     'UAC Status enabled?' = 'Offline/Access issue'
                                  'Windows No Auto Update?'= 'Offline/Access issue'
                                        'Windows Defender' = 'Offline/Access issue'
                                        'A2rm Daily Task'  = 'Offline/Access issue'
                                        'AppD Daily Task'  = 'Offline/Access issue'
                                        'Lesa Local Admin' = 'Offline/Access issue'
                       'Local admin server Security Group' = 'Offline/Access issue'
                            'Powershell Remoting Enabled?' = 'Offline/Access issue'
                             'Powershell Execution Policy' = 'Offline/Access issue'
                   'specter Feature Settings OverrideMask' = 'Offline/Access issue'
                        'specter FeatureSettings Override' = 'Offline/Access issue'
                   'specter FeatureSettings QualityCompat' = 'Offline/Access issue'
                   'Security Registry Fix entry for \\\\*\\NETLOGON' = 'Offline/Access issue'
                   'Security Registry Fix entry for \\\\*\\SYSVOL' = 'Offline/Access issue'
                   'Security Registry Fix entry for \\*\NETLOGON' = 'Offline/Access issue'
                   'Security Registry Fix entry for \\*\SYSVOL' = 'Offline/Access issue'
                   'SNMP Permitted Managers Entry 1' = 'Offline/Access issue'
                   'SNMP Permitted Managers Entry 2' = 'Offline/Access issue'
                   'SNMP Permitted Managers Entry 3' = 'Offline/Access issue'
                   'Trap Config For LDNPRV321654' = 'Offline/Access issue'
                   'Trap Config For LDNPUB321654' = 'Offline/Access issue'
                              'Proxy Configured?' = 'Offline/Access issue'
                                  'Telnet Client' = 'Offline/Access issue'
                                  'SNMP-Service' = 'Offline/Access issue'
                                            IPAddress = 'Offline/Access issue'
                                            SubnetMask = 'Offline/Access issue'
                                           DefaultGateway = 'Offline/Access issue'
                                           DHCPEnabled = 'Offline/Access issue'
                                           DnsServer = 'Offline/Access issue'
                                           'Recent patch Date' = 'Offline/Access issue'
                                               }
  
  }
 }
   

   $final | export-csv -Path C:\temp\DCBuild.csv -NoTypeInformation
