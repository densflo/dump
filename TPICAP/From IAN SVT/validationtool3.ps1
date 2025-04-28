

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
            $Cache:VCSession = Connect-VIServer -Server $Cache:vCenterServer -Credential $Cache:Creds -ErrorAction Continue
            
        }
        catch{
            $Cache:EndpointError = $_.Exception.Message
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
                                                       New-UDTable -Title "Drives" -Headers @("Drive","FreeSpace GB","Total Space GB") -Endpoint {
                                                       Get-WmiObject win32_logicaldisk -ComputerName $Servername -Credential $creds  -ErrorAction SilentlyContinue | Where-Object {$_.DriveType -eq '3'}  | Select-Object deviceID,@{n="FreeSpace";e={ [Math]::truncate($_.FreeSpace / 1GB)}},@{n="size";e={ [Math]::truncate($_.Size / 1GB)}} | Out-UDTableData -Property @("DeviceID","FreeSpace","size")}
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



$pages += New-UDPage -name "VMware" -Content {

              
 New-UDLayout -Columns 1 -Content { 
 New-UDColumn -LargeSize 12 {

   New-UDTabContainer -Tabs {



                           New-UDTab -Text 'Important'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LD5PINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LD5PINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 Get-VMHost -Server njcesxvsvc01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"njcesxvsvc01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate')  
                                 Get-VMHost -Server sngpinfvca01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"sngpinfvca01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate')
                                 Get-VMHost -Server arkpinfvca01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"arkpinfvca01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 Get-VMHost -Server LDNPINFVCA02 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCA02"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 Get-VMHost -Server LDNPINFVCS01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCS01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 Get-VMHost -Server LDNPINFVCS02 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCS02"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 Get-VMHost -Server SYDPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SYDPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate')
                                 Get-VMHost -Server SYDPINFVCA02 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SYDPINFVCA02"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate')
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 15
                                    
                                    Get-Datastore -Server LD5PINFVCA01 | Select @{N="Vcenter";E={"LD5PINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    Get-Datastore -Server njcesxvsvc01 | Select @{N="Vcenter";E={"njcesxvsvc01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    Get-Datastore -Server sngpinfvca01 | Select @{N="Vcenter";E={"sngpinfvca01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    Get-Datastore -Server arkpinfvca01 | Select @{N="Vcenter";E={"arkpinfvca01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server arkpinfvca01,LD5PINFVCA01,njcesxvsvc01,sngpinfvca01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
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
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 16

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server LD5PINFVCA01,njcesxvsvc01,sngpinfvca01,arkpinfvca01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms njcesxvsvc01" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           


                                  

                              }
                           
                           


                           }
              
                           }
                           New-UDTab -Text 'Vcenter Alarms' -Content {
                           
                           New-UDGrid -PageSize 40 -Title "Alert Progress to Red" -NoPaging -Headers @('CreatedTime','Message','Entity','Host','Vm','Vcenter') -Properties @('CreatedTime','Message','Entity','Host','Vm','Vcenter') -Endpoint {
                           
                            $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret

                            $AlarmEvents1 = Get-VIEvent -Server LD5PINFVCA01 -Start (Get-Date).AddDays(-7) -MaxSamples ([int]::MaxValue) | Where {$_ -is [VMware.Vim.AlarmStatusChangedEvent] -and ($_.To -eq "Red" )} | Select CreatedTime,@{N="Message";E={[string]$_.FullFormattedMessage}},@{N="Entity";E={$_.Entity.Name}},@{N="Host";E={$_.Host.Name}},@{N="Vm";E={$_.Vm.Name}},@{N="Vcenter";E={"LD5PINFVCA01"}} 
                            $AlarmEvents2 = Get-VIEvent -Server njcesxvsvc01 -Start (Get-Date).AddDays(-7) -MaxSamples ([int]::MaxValue) | Where {$_ -is [VMware.Vim.AlarmStatusChangedEvent] -and ($_.To -eq "Red" )} | Select CreatedTime,@{N="Message";E={[string]$_.FullFormattedMessage}},@{N="Entity";E={$_.Entity.Name}},@{N="Host";E={$_.Host.Name}},@{N="Vm";E={$_.Vm.Name}},@{N="Vcenter";E={"njcesxvsvc01"}} 
                            $AlarmEvents3 = Get-VIEvent -Server sngpinfvca01 -Start (Get-Date).AddDays(-7) -MaxSamples ([int]::MaxValue) | Where {$_ -is [VMware.Vim.AlarmStatusChangedEvent] -and ($_.To -eq "Red" )} | Select CreatedTime,@{N="Message";E={[string]$_.FullFormattedMessage}},@{N="Entity";E={$_.Entity.Name}},@{N="Host";E={$_.Host.Name}},@{N="Vm";E={$_.Vm.Name}},@{N="Vcenter";E={"sngpinfvca01"}} 
                            $AlarmEvents4 = Get-VIEvent -Server arkpinfvca01 -Start (Get-Date).AddDays(-7) -MaxSamples ([int]::MaxValue) | Where {$_ -is [VMware.Vim.AlarmStatusChangedEvent] -and ($_.To -eq "Red" )} | Select CreatedTime,@{N="Message";E={[string]$_.FullFormattedMessage}},@{N="Entity";E={$_.Entity.Name}},@{N="Host";E={$_.Host.Name}},@{N="Vm";E={$_.Vm.Name}},@{N="Vcenter";E={"arkpinfvca01"}} 
                             
                             $AlarmEvents1,$AlarmEvents2,$AlarmEvents3,$AlarmEvents4 | sort CreatedTime -Descending |Out-UDGridData

                              }
                           
                           }
                           New-UDTab -Text 'Logs'           -Content {
                             
                             New-UDGrid -PageSize 40 -Title "VCenter Error Events" -NoPaging -Headers @("Vcenter","Timestamp", "Message") -Properties @("Vcenter","CreatedTime", "FullFormattedMessage") -Endpoint {


                               
                               $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret

                               Start-Sleep 18

                             $events1 = Get-VIEvent -Server LD5PINFVCA01 -types error, warning | select @{N="Vcenter";E={"LD5PINFVCA01"}},CreatedTime,FullFormattedMessage 
                             $events2 = Get-VIEvent -Server njcesxvsvc01 -types error, warning | select @{N="Vcenter";E={"njcesxvsvc01"}},CreatedTime,FullFormattedMessage 
                             $events3 = Get-VIEvent -Server sngpinfvca01 -types error, warning | select @{N="Vcenter";E={"sngpinfvca01"}},CreatedTime,FullFormattedMessage 
                             $events4 = Get-VIEvent -Server arkpinfvca01 -types error, warning | select @{N="Vcenter";E={"arkpinfvca01"}},CreatedTime,FullFormattedMessage 
   
                                 $events1,$events2,$events3,$events4 | sort CreatedTime -Descending | Out-UDGridData

                            }
                        
                 }
                           New-UDTab -Text 'Hosts Info'     -Content {
                       
                           New-UDGrid -PageSize 40 -Title "ESXi Details" -NoPaging -Headers @("Name","ConnectionState", "Powerstate","NumCPU","CpuTotalMhz","MemoryUsageGB","MemoryTotalGB","Version","Vcenter") -Properties @("Name","ConnectionState", "Powerstate","NumCPU","CpuTotalMhz","MemoryUsageGB","MemoryTotalGB","Version","Vcenter") -Endpoint {
                           
                           $vcenter1 = "LD5PINFVCA01"
                           $vcenter2 = "njcesxvsvc01"
                           $vcenter3 = "sngpinfvca01"
                           $vcenter4 = "arkpinfvca01"

                           $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret

                           $vcenterHost1 = Get-VMHost -Server $vcenter1 | select Name,@{N="ConnectionState";E={[string]$_.ConnectionState}},@{N="Powerstate";E={[string]$_.Powerstate}},@{N="NumCPU";E={[string]$_.NumCPU}},CpuTotalMhz,@{N="MemoryUsageGB";E={[math]::Round(($_.MemoryUsageGB))}},@{N="MemoryTotalGB";E={[math]::Round(($_.MemoryTotalGB))}},Version,@{N="Vcenter";E={$vcenter1}}
                           $vcenterHost2 = Get-VMHost -Server $vcenter2 | select Name,@{N="ConnectionState";E={[string]$_.ConnectionState}},@{N="Powerstate";E={[string]$_.Powerstate}},@{N="NumCPU";E={[string]$_.NumCPU}},CpuTotalMhz,@{N="MemoryUsageGB";E={[math]::Round(($_.MemoryUsageGB))}},@{N="MemoryTotalGB";E={[math]::Round(($_.MemoryTotalGB))}},Version,@{N="Vcenter";E={$vcenter2}}
                           $vcenterHost3 = Get-VMHost -Server $vcenter3 | select Name,@{N="ConnectionState";E={[string]$_.ConnectionState}},@{N="Powerstate";E={[string]$_.Powerstate}},@{N="NumCPU";E={[string]$_.NumCPU}},CpuTotalMhz,@{N="MemoryUsageGB";E={[math]::Round(($_.MemoryUsageGB))}},@{N="MemoryTotalGB";E={[math]::Round(($_.MemoryTotalGB))}},Version,@{N="Vcenter";E={$vcenter3}}
                           $vcenterHost4 = Get-VMHost -Server $vcenter4 | select Name,@{N="ConnectionState";E={[string]$_.ConnectionState}},@{N="Powerstate";E={[string]$_.Powerstate}},@{N="NumCPU";E={[string]$_.NumCPU}},CpuTotalMhz,@{N="MemoryUsageGB";E={[math]::Round(($_.MemoryUsageGB))}},@{N="MemoryTotalGB";E={[math]::Round(($_.MemoryTotalGB))}},Version,@{N="Vcenter";E={$vcenter4}}

                           $vcenterHost1,$vcenterHost2,$vcenterHost3,$vcenterHost4 | Out-UDGridData 
                           
                           }
                   
              
                           }
                           New-UDTab -Text 'Data Store'     -Content {
                       
                           New-UDGrid -PageSize 40 -Title "ESXi Details" -NoPaging -Headers @('DataStoreName','Free Space(GB)','Capacity (GB)','Percentage Free Space(%)','Vcenter') -Properties @('DataStoreName','Free Space(GB)','Capacity (GB)','Percentage Free Space(%)','Vcenter') -Endpoint{
                           
                           $vcenter1 = "LD5PINFVCA01"
                           $vcenter2 = "njcesxvsvc01"
                           $vcenter3 = "sngpinfvca01"
                           $vcenter4 = "arkpinfvca01"

                           $null = Connect-VIServer -Server $Cache:ViServerList.Name -Session $Cache:ViServerList.SessionSecret

                           $datastore1 = Get-Datastore -Server $vcenter1  | Select @{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Capacity (GB)";E={[math]::Round(($_.CapacityGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}},@{N="Vcenter";E={$vcenter1}}
                           $datastore2 = Get-Datastore -Server $vcenter2  | Select @{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Capacity (GB)";E={[math]::Round(($_.CapacityGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}},@{N="Vcenter";E={$vcenter2}}
                           $datastore3 = Get-Datastore -Server $vcenter3  | Select @{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Capacity (GB)";E={[math]::Round(($_.CapacityGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}},@{N="Vcenter";E={$vcenter3}}
                           $datastore4 = Get-Datastore -Server $vcenter4  | Select @{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Capacity (GB)";E={[math]::Round(($_.CapacityGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}},@{N="Vcenter";E={$vcenter4}}

                           $datastore1,$datastore2,$datastore3,$datastore4 | Out-UDGridData
  
  
  
                           
                           
                           }
                   
              
              }
                            



                           }
}

                            
               }

}
    
     


$ei = New-UDEndpointInitialization -Module @("C:\Program Files\WindowsPowerShell\Modules\VMware.VimAutomation.Core\10.1.0.8344055\VMware.VimAutomation.Core.psm1")
$Dashboard = New-UDDashboard  -Title 'Server Validation Tool v1.5' -Theme $theme  -Page $pages -EndpointInitialization $ei -Footer $footer 
Start-UDDashboard -Port 10001 -Dashboard $Dashboard -Endpoint @($Schedule)

