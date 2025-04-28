

Get-UDDashboard | Stop-UDDashboard

Get-Module -All | Import-Module

$theme = Get-UDTheme 'azure'




$null = Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Scope User -Confirm:$false
$Cache:Creds = Get-Credential -Credential $(whoami)

#####
$Every60Sec = New-UDEndpointSchedule -Every 60 -Second
$Schedule = New-UDEndpoint -Schedule $Every60Sec -Endpoint {
    $Cache:EndpointError = $false
    $Cache:vCenterServer = Get-Content -Path D:\dashboard\vcenter.txt 
    if (!($global:DefaultVIServer.Name -eq $Cache:vCenterServer)){
        try{
            $Cache:VCSession = Connect-VIServer -Server $Cache:vCenterServer -Credential $Cache:Creds -ErrorAction SilentlyContinue
            
        }
        catch{
            $Cache:EndpointError = $_.Exception.Message
            $Cache:EndpointError | D:\dashboard\vcentererror.log
        }
    }
    $Cache:ViServerList = $global:DefaultVIServer
}




  

  

  
$footer =  New-UDFooter -Copyright "Created and Developed by Ian Navarrete 2020"
$pages = @()

$pages += New-UDPage -name "SVT" -Content {


New-UDLayout -Columns 1 -Content {

New-UDColumn -SmallSize 3 {
                           New-UDIcon  -Icon windows -Size 4x 
                           New-UDInput  -Title "Test Server Connection"  -Endpoint{ param($servercheck) 
                                                              
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {
                                         New-UDTable -Title "$servercheck Ping" -AutoRefresh  -Headers @("Name","Ping Status","FQDN") -Endpoint {

                                   $ping = if(Test-Connection -ComputerName $servercheck -Quiet -Count 1) {
                                            New-Object -TypeName PSCustomObject -Property @{
                                             Name = $servercheck
                                            'Ping Status' = 'Ok'
                                            'FQDN' = [net.dns]::GetHostEntry($servercheck).Hostname
                                                }
                                                    } else {
                                                                New-Object -TypeName PSCustomObject -Property @{
                                                                Name = $servercheck
                                                               'Ping Status' = 'Failed'
                                                               'FQDN' = [net.dns]::GetHostEntry($servercheck).Hostname
                                                                } 
                                                                 } 

                                                    $ping  | Out-UDTableData -Property @("Name","Ping Status","FQDN")
                                                                    } 

                                                                        
                                            
                                            
                                            

                                         }
                                         }
                                         } -SubmitText "Test"
                                           
                           

                          }

New-UDColumn -LargeSize 12 {
                             New-UDInput   -Title "Windows Server Login Details"   -Content {
       
                                New-UDInputField -Type textbox -Name ServerName -Placeholder 'Server Name'
                                New-UDInputField -Type textbox -Name UserName -Placeholder 'User Name with domain'
                                New-UDInputField -Type password -Name Password -Placeholder 'Password'
       
       
       } -SubmitText "Connect" -Endpoint{
       
                        Param($ServerName,$username,$password )


                        $pass =  ConvertTo-SecureString -String $password -AsPlainText -Force
                        $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass
                        


                        New-UDInputAction  -Content{

                               New-UDCard -Title "$ServerName Health Details" -TitleAlignment center  -Content {
                               
                                      

                                    }
                               
                            New-UDTabContainer -Tabs {
                            
                             New-UDTab -Text 'Server Info'  -Content {                          
	                           New-UDColumn -Size 3 {  
                                                       New-UDTable -Title  "Server Information" -Headers @(" ", " ") -Endpoint {
                                                       $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                    @{
                                                       'Computer Name' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).Name
                                                       'Operating System' = (Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem).Caption
                                                       'Domain' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).Domain
                                                       'Physical Memory' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).TotalPhysicalMemory / 1GB | ForEach-Object { "$([Math]::Round($_, 2)) GBs " }
                                                       'Model' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).Model
                                                       'Manufacturer' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).Manufacturer

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
                                                      }
                                                       New-udtable -Title  "CPU and Mem Utilization" -AutoRefresh -Headers @("CPU %","Memory %")-Endpoint{ 
                                                       
                                                       $Array = @()
 

                                                       $Check = $Processor = $ComputerMemory = $RoundMemory = $Object = $null
                                                       $Servername = $Servername.trim()
 
    
                                                       # Processor utilization
                                                       $Processor = (Get-WmiObject -ComputerName $Servername -Class win32_processor -Credential $creds -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average | Select-Object Average).Average
 
                                                       # Memory utilization
                                                       $ComputerMemory = Get-WmiObject -ComputerName $Servername -Credential $creds -Class win32_operatingsystem -ErrorAction Stop
                                                       $Memory = ((($ComputerMemory.TotalVisibleMemorySize - $ComputerMemory.FreePhysicalMemory)*100)/ $ComputerMemory.TotalVisibleMemorySize)
                                                       $RoundMemory = [math]::Round($Memory, 2)
         
                                                       # Creating custom object
                                                       $Object = New-Object PSCustomObject
                                                       $Object | Add-Member -MemberType NoteProperty -Name "CPU %" -Value $Processor
                                                       $Object | Add-Member -MemberType NoteProperty -Name "Memory %" -Value $RoundMemory
 
        
                                                       $Array += $Object
    
                                                       $Array | Out-UDTableData -Property @("CPU %","Memory %")
                                                       
                                                       } 
                                                       New-UDTable -Title  "UpTime" -AutoRefresh -Headers @('Last Boot','Uptime') -Endpoint {

                                                           $userSystem = Get-WmiObject win32_operatingsystem -ComputerName $ServerName -Credential $creds -ErrorAction SilentlyContinue 
                                                           
                                                           $sysuptime= (Get-Date) - $userSystem.ConvertToDateTime($userSystem.LastBootUpTime)
                                                           $lastboot = ($userSystem.ConvertToDateTime($userSystem.LastBootUpTime) )
                                                           $uptime = ([string]$sysuptime.Days + " Days " + $sysuptime.Hours + " Hours " + $sysuptime.Minutes + " Minutes" ) 
                                                           $propHash = [ordered]@{
                                                                  
                                                                BootTime     = $lastboot 
                                                                Uptime       = $Uptime
                                                           
                                                               }
                                                            $objComputerUptime = New-Object PSOBject -Property $propHash 
                                                            $objComputerUptime  | Out-UDTableData -Property @("BootTime","Uptime")
                         
                                                               }
                                                       New-UDTable -Title  "APPD Service Monitoring" -AutoRefresh -Headers @("Name","StartMode","State","Status") -Endpoint {
                           $AppdAgent        = if (Get-WMIObject -Query "select * from win32_service where name='Appdynamics Machine Agent'" -computer $ServerName -Credential $creds){
                                             Get-WMIObject -Query "select * from win32_service where name='Appdynamics Machine Agent'" -ComputerName $ServerName -Credential $creds |select name,startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Name      = "Appdynamics Machine Agent"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} }
                           $SnareAgent       = if (Get-WMIObject -Query "select * from win32_service where name='Snare'"                     -computer $ServerName -Credential $creds){
                                             Get-WMIObject -Query "select * from win32_service where name='Snare'" -ComputerName $ServerName -Credential $creds |select name,startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Name      = "Snare"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} }
                           $NTListenerAgent  = if (Get-WMIObject -Query "select * from win32_service where name='tmlisten'"                  -computer $ServerName -Credential $creds){
                                             Get-WMIObject -Query "select * from win32_service where name='tmlisten'" -ComputerName $ServerName -Credential $creds|select @{N="Name";E={"NT Listener"}},startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Name      = "NT Listener"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} }
                           $NTScanAgent      = if (Get-WMIObject -Query "select * from win32_service where name='ntrtscan'"                  -computer $ServerName -Credential $creds){
                                             Get-WMIObject -Query "select * from win32_service where name='ntrtscan'"                        -Computer $ServerName -Credential $creds |select @{N="Name";E={"NT Real Time Scan"}},startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Name      = "NT Real Time Scan"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} }


                                                                                                
                                                                        $AppdAgent,$SnareAgent,$NTListenerAgent,$NTScanAgent | Out-UDTableData -Property @("Name","StartMode","State","Status")

                                                               }
                                                       New-UDButton -text "More Services" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {

                                         New-UDInput -Title "Stop A Service" -Content {
                                           
                                            New-UDInputField -Type textbox -Name ServiceName -Placeholder 'Service Name'
                                         
                                           } -SubmitText "Stop" -Endpoint {
                                               Param($servicename)

                                              $sess = New-PSSession -ComputerName $servername -Credential $creds
                                              $scriptBlockStop = { param ($service)
     
                                                             Stop-Service -Name $service
                                                             }
                                                 
                                                 

                                               Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop -ArgumentList "$servicename"
                                                                          
                                               Show-UDToast -Message "successfully Stopped $servicename on $servername" -BackgroundColor green -Duration 10000
                                                                          
                                                                          

                                              Remove-PSSession -Session $sess
                                           
                                           
                                           
                                           }

                                         New-UDInput -Title "Start A Service" -Content {
                                           
                                            New-UDInputField -Type textbox -Name ServiceName -Placeholder 'Service Name'
                                         
                                           } -SubmitText "Start" -Endpoint {
                                               Param($servicename)

                                              $sess = New-PSSession -ComputerName $servername -Credential $creds
                                              $scriptBlockStart = { param ($service)
     
                                                             Start-Service -Name $service
                                                             }
                                                 
                                                 

                                               (Invoke-Command -Session $sess -ScriptBlock $scriptBlockStart -ArgumentList "$servicename")
                                                                          
                                               Show-UDToast -Message "successfully Started $servicename on $servername" -BackgroundColor green -Duration 10000
                                                                          
                                                                          

                                                Remove-PSSession -Session $sess
                                           
                                           
                                           
                                           }

                                         New-UDTable -Title "$servername Services" -Headers @("name","StartMode","State","Status") -Endpoint {

                                         Get-WmiObject -ComputerName $servername -Credential $creds -Class Win32_Service | select name, startmode, state, status | sort state | Out-UDTableData -Property @("name","StartMode","State","Status")

                                         }
                                        }
                                         
                                       }
                                      }
                                                       New-UDTable -Title  "Network Details"  -Headers @("IPAddress","SubnetMask","Gateway","DNSServers","MACAddress") -Endpoint {

                                                       $Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ServerName -Credential $creds -EA Stop | ? {$_.IPEnabled}

                                                                    $IPAddress  = $Network.IpAddress[0]            
                                                                   $SubnetMask  = $Network.IPSubnet[0]            
                                                                $DefaultGateway = [string]$Network.DefaultIPGateway            
                                                                   $DNSServers  = $Network.DNSServerSearchOrder            
                                                                 $IsDHCPEnabled = $false            
                                                                             If($network.DHCPEnabled) {            
                                                                             $IsDHCPEnabled = $true            
                                                                                                    }            
                                                                   $MACAddress  = $Network.MACAddress            
                                                                   $OutputObj  = New-Object -Type PSObject                        
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name Gateway -Value $DefaultGateway
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value $DNSServers            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress            
                                                                   $OutputObj | Out-UDTableData -Property @("IPAddress","SubnetMask","Gateway","DNSServers","MACAddress")} 
                                                           
                                                                    }        
			                   New-UDColumn -Size 3 {  
                                                       New-UdMonitor -Title "Disk Perfomance" -Type Line  -RefreshInterval 5 -ChartBackgroundColor @("#80962F23","#8014558C",'#80FF6B63') -ChartBorderColor @('#FFFF6B63','#80962F23','#82C0CFA' ) -Label @('Avg Disk Queue','Current Disk Queue','Read') -Endpoint { 
                                                       Out-UDMonitorData -Data @(

                                                       Get-Counter -ComputerName $ServerName '\PhysicalDisk(0 C:)\Avg. Disk Queue Length'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue  
                                                       Get-Counter -ComputerName $ServerName '\PhysicalDisk(0 C:)\Current Disk Queue Length'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue 
                                                       Get-Counter -ComputerName $ServerName '\PhysicalDisk(0 C:)\\PhysicalDisk(0 C:)\% Disk Read Time'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue        
                                                                ) 
		                                                     }
                                                       New-UDChart -Title "C Disk Space"  -Type Doughnut  -Endpoint {  
                                                           try {
                                                                $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                 
                                                                Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk  | Where-Object {$_.DriveType -eq '3'} | Select-Object -First 3 -Property DeviceID,Size,FreeSpace | ForEach-Object {
                                                                @([PSCustomObject]@{
                                                                                    Label = "Used Space"
                                                                                    Data = [Math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2);
                                                                                      },
                                                                  [PSCustomObject]@{
                                                                                    Label = "Free Space"
                                                                                    Data = [Math]::Round($_.FreeSpace / 1GB, 2);
                                                                                                                           }) | Out-UDChartData -DataProperty "Data" -LabelProperty "Label" -BackgroundColor @("#80FF6B63","#8028E842") -HoverBackgroundColor @("#80FF6B63","#8028E842") -BorderColor @("#80FF6B63","#8028E842") -HoverBorderColor @("#F2675F","#68e87a")
                                                                                        }
                                                                                       }
                                                            catch {
                                                                    0 | Out-UDChartData -DataProperty "Data" -LabelProperty "Label"
                                                                     }
                                                                                                                                 }
                                                       New-UDTable -Title "Drives" -Headers @("Drive","FreeSpace GB","Total Space GB","used %") -Endpoint {
                                                       Get-WmiObject win32_logicaldisk -ComputerName $Servername -Credential $creds  -ErrorAction SilentlyContinue | Where-Object {$_.DriveType -eq '3'}  | Select-Object deviceID,@{n="FreeSpace";e={ [Math]::truncate($_.FreeSpace / 1GB)}},@{n="size";e={ [Math]::truncate($_.Size / 1GB)}},@{L='used %';E={"{0:N2}" -f (($_.freespace/$_.size)*100)}} | Out-UDTableData -Property @("DeviceID","FreeSpace","size","used %")}
                                                       New-UDTable -Title "Paging Info" -AutoRefresh -Headers @("Name","Size","PeakUsage GB","CurrentUsage GB") -Endpoint {
                                                                  $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                                    
                                                                                Get-CimInstance -CimSession $session -ClassName win32_pagefileusage | select name,@{n="AllocatedBaseSize GB";Expression = {[math]::round($_.AllocatedBaseSize / 1KB, 2)}},@{n="PeakUsage GB";Expression = {[math]::round($_.PeakUsage / 1KB, 2)}},@{n="CurrentUsage GB";Expression = {[math]::round($_.CurrentUsage / 1KB, 2)}} | Out-UDTableData -Property @("Name","AllocatedBaseSize GB","PeakUsage GB","CurrentUsage GB")



                                                                                 }
                                                        


                                                             }
                               New-UDColumn -Size 3 {
                                                        New-UdMonitor -Title "CPU (% processor time)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                                                        Get-Counter -ComputerName $ServerName '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
		                                                     }
                                                        New-UDTable -Title "CPU Core Usage" -AutoRefresh -Headers @("Logical Core","Usage %") -Endpoint{

                                                        $res = Get-WmiObject -ComputerName $servername -Credential $creds -Query "select Name, PercentProcessorTime from Win32_PerfFormattedData_PerfOS_Processor" | Where-Object {$_.name -notmatch '_total' } |sort name

                                                        foreach ($single in $res){
                                                                New-Object pscustomobject -Property @{
    
                                                                 cookedvalue = $single.PercentProcessorTime
                                                                 name = $single.Name
                                                                                   } | Out-UDTableData -Property @("Name","cookedvalue")
                                                                   } 

                                                          }
                                                        New-UDTable -Title "Top 10 CPU process" -AutoRefresh -Headers @("Name","PercentProcessorTime") -Endpoint {
                                                       
                                                                gwmi -computername $ServerName Win32_PerfFormattedData_PerfProc_Process -Credential $creds|Where-Object {$_.name -notmatch '_total|idle|svchost#'} |sort PercentProcessorTime -desc | select Name,PercentProcessorTime | Select -First 10 | Out-UDTableData -Property @("Name","PercentProcessorTime")

                                                       }
                                                       
                                                       }
                               New-UDColumn -Size 3 {  
                                                       New-UdMonitor -Title "Memory Performance" -Type Line  -RefreshInterval 5 -ChartBackgroundColor @("#80962F23","#8014558C",'#80FF6B63') -ChartBorderColor @('#FFFF6B63','#80962F23','#82C0CFA' ) -Label @('Commit','Available','Faults/sec') -Endpoint { 
                                                       Out-UDMonitorData -Data @(

                                                       Get-Counter -ComputerName $ServerName '\memory\% committed bytes in use'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue  
                                                       Get-Counter -ComputerName $ServerName '\memory\Available Mbytes'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
                                                       Get-Counter -ComputerName $ServerName '\Memory\Cache Faults/sec'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
                                                                
                                                                ) 
		                                                     }
                                                       New-UDChart -Title "Physical memory Usage" -AutoRefresh -Type Doughnut -Endpoint {  
                                                                 $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                
                                                                 
                                                                Get-CimInstance -CimSession $session -ClassName win32_operatingsystem   | select -Property TotalVisibleMemorySize, FreePhysicalMemory | ForEach-Object {
                                                                @([PSCustomObject]@{
                                                                                    Label = "Used Memory /GB"
                                                                                    Data = [Math]::Round(($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / 1MB,2);
                                                                                      },
                                                                  [PSCustomObject]@{
                                                                                    Label = "Free Memory /GB"
                                                                                    Data = [Math]::Round($_.FreePhysicalMemory / 1MB,2);
                                                                                                                           }) | Out-UDChartData -DataProperty "Data" -LabelProperty "Label" -BackgroundColor @("#80FF6B63","#8028E842") -HoverBackgroundColor @("#80FF6B63","#8028E842") -BorderColor @("#80FF6B63","#8028E842") -HoverBorderColor @("#F2675F","#68e87a")
                                                                                        }
                                                                                       
                                                            
                                                                                                                                 }
                                                       New-udtable -Title  "Top 10 Memory process " -AutoRefresh -Headers @("Name","Private Memory(GB)") -Endpoint {
                                                       
                                                       gwmi -computername $ServerName -Credential $creds Win32_Process | Sort WorkingSetSize -Descending | Select Name,@{n="Private Memory(GB)";Expression = {[math]::round($_.WorkingSetSize / 1GB, 2)}} | Select -First 10 | Out-UDTableData -Property @("Name","Private Memory(GB)")
                                                       
                                                       }
                                                       
                                                       
                                                       }
                                                       }
                                                                    
                              New-UDTab -Text 'Events' -Content {
                                                                      
                                                                      New-UDGrid -Title "$servername System and Application events for past 24 hours" -PageSize 30 -Headers @("ProviderName","TimeCreated","Id","LevelDisplayName","Message") -Properties @("ProviderName","TimeCreated","Id","LevelDisplayName","Message") -Endpoint {
                                                                      
                                                                      
                                                                                                    $days = (Get-Date).AddHours(-24)
                                                                                                    $range = $days.ToShortDateString();


                                                                                          Get-Winevent -ComputerName $servername -Credential $creds -FilterHashtable @{LogName="System","Application"; Level=1,2,3; startTime=$range} | select providername, TimeCreated, Id, LevelDisplayName, Message   | Out-UDGridData
                                                                      
                                                                      
                                                                                                                               } 
                                                                     
                                                                     }

                                                       }
		   }
			                                                  
          }
	     }
        }                     
       }
$pages += New-UDPage -name "VMware Morning Checks EMEA" -Content {

              
 New-UDLayout -Columns 1 -Content { 
 New-UDColumn -LargeSize 12 {

                        
                         New-UDCard -Title "EMEA Vcenter Health Details" -TitleAlignment center  -Content {
                               
                                      

                                    }
                         New-UDTabContainer -Tabs {



                           New-UDTab -Text 'LDNPINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LDNPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LDNPINFVCA01| Select @{N="Vcenter";E={"LDNPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LDNPINFVCA01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost -Server LDNPINFVCA01){

                                $hs = Get-View -Server LDNPINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()

                             $vcenteralarm = Get-TriggeredAlarms -vCenter LDNPINFVCA01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'LDNPINFVCA02'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LDNPINFVCA02 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCA02"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LDNPINFVCA02| Select @{N="Vcenter";E={"LDNPINFVCA02"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LDNPINFVCA02 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost -Server LDNPINFVCA02){

                                $hs = Get-View -Server LDNPINFVCA02 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter LDNPINFVCA02

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'LDNPINFVCS01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LDNPINFVCS01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCS01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LDNPINFVCS01| Select @{N="Vcenter";E={"LDNPINFVCS01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LDNPINFVCS01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server LDNPINFVCA02 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms LDNPINFVCS01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'LDNPINFVCS02'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LDNPINFVCS02 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCS02"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LDNPINFVCS02| Select @{N="Vcenter";E={"LDNPINFVCS02"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LDNPINFVCS02 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server LDNPINFVCA02 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter LDNPINFVCS02

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'ARKPINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server ARKPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"ARKPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server ARKPINFVCA01 | Select @{N="Vcenter";E={"ARKPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server ARKPINFVCA01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 16

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server ARKPINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter ARKPINFVCA01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'LD5PINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LD5PINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LD5PINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LD5PINFVCA01 | Select @{N="Vcenter";E={"LD5PINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LD5PINFVCA01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 16

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server LD5PINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter LD5PINFVCA01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           
                           

                           }
                    }


                            
               }

}
$pages += New-UDPage -name "VMware Morning Checks APAC" -Content {

              
 New-UDLayout -Columns 1 -Content { 
 New-UDColumn -LargeSize 12 {

                        
                         New-UDCard -Title "APAC Vcenter Health Details" -TitleAlignment center  -Content {
                               
                                      

                                    }
                         New-UDTabContainer -Tabs {



                          
                           New-UDTab -Text 'SYDPINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server SYDPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SYDPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server SYDPINFVCA01 | Select @{N="Vcenter";E={"SYDPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server SYDPINFVCA01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 16

                                foreach($esx in Get-VMHost -Server SYDPINFVCA01){

                                $hs = Get-View -Server SYDPINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter SYDPINFVCA01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'SYDPINFVCA02'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server SYDPINFVCA02 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SYDPINFVCA02"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server SYDPINFVCA02 | Select @{N="Vcenter";E={"SYDPINFVCA02"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server SYDPINFVCA02 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost -Server SYDPINFVCA02){

                                $hs = Get-View -Server SYDPINFVCA02 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter SYDPINFVCA02

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'SNGPINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server SNGPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SNGPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server SNGPINFVCA01 | Select @{N="Vcenter";E={"SNGPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server SNGPINFVCA01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server SNGPINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter SNGPINFVCA01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }

                           }
                    }


                            
               }

}
$pages += New-UDPage -name "VMware Morning Checks AMER" -Content {

              
 New-UDLayout -Columns 1 -Content { 
 New-UDColumn -LargeSize 12 {

                        
                         New-UDCard -Title "AMER Vcenter Health Details" -TitleAlignment center  -Content {
                               
                                      

                                    }
                         New-UDTabContainer -Tabs {

                           New-UDTab -Text 'njcesxvsvc01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server njcesxvsvc01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"njcesxvsvc01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server njcesxvsvc01 | Select @{N="Vcenter";E={"njcesxvsvc01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server njcesxvsvc01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server njcesxvsvc01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


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

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter njcesxvsvc01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           

                           }
                    }


                            
               }

}
    
     


$ei = New-UDEndpointInitialization -Module @("C:\Program Files\WindowsPowerShell\Modules\VMware.VimAutomation.Core\10.1.0.8344055\VMware.VimAutomation.Core.psm1")
$Dashboard = New-UDDashboard  -Title 'Server Validation Tool v1.5' -Theme $theme -FontColor white -NavBarFontColor white -Page $pages -EndpointInitialization $ei -Footer $footer 
Start-UDDashboard -Port 10002 -Dashboard $Dashboard -Endpoint @($Schedule)

