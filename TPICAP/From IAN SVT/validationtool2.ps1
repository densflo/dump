Remove-Variable * -ErrorAction SilentlyContinue

Get-UDDashboard | Stop-UDDashboard

Get-Module -All | Import-Module

$theme = Get-UDTheme 'azure'





$Every60Sec = New-UDEndpointSchedule -Every 60 -Second
$Schedule = New-UDEndpoint -Schedule $Every60Sec -Endpoint {

    $Cache:vCenterServer = $vcenters
    if (!($global:DefaultVIServer.Name -eq $Cache:vCenterServer)){
        try{
            Connect-VIServer -Server $Cache:vCenterServer -Credential $Cache:Creds -ErrorAction SilentlyContinue
        }
        catch{
            $err = $_.Exception.Message
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

                                                            if(Test-Connection -ComputerName $servercheck -Count 1){New-UDInputAction -Toast "Ping Successful $servercheck"  -Duration 5000}
                                                             else{New-UDInputAction -Toast "Ping Failed $servercheck"}
                                                             } -SubmitText "Test"
                           

                          }

New-UDColumn -LargeSize 12 {
                             New-UDInput   -Title "Windows Server Login Details"   -Content {
       
                                New-UDInputField -Type textbox -Name ServerName -Placeholder 'Server Name'
                                New-UDInputField -Type textbox -Name UserName -Placeholder 'User Name'
                                New-UDInputField -Type password -Name Password -Placeholder 'Password'
       
       
       } -SubmitText "Connect" -Endpoint{
       
                        Param($ServerName,$username,$password )

                        $pass =  ConvertTo-SecureString -String $password -AsPlainText -Force
                        $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass
                        


                        New-UDInputAction  -Content{

                               New-UDCard -Title "$ServerName Health Details" -TitleAlignment center  -Content { 
                               
                               New-UDButton -Icon arrow_circle_left -IconAlignment right -OnClick {   
                                                                                                    New-UDEndpoint -Endpoint {  
                                                                                                                                $getcimid = Get-CimSession
                                                                                                                                Remove-CimSession  -Id $getcimid.InstanceId

                                                                                                                              } -ArgumentList @($getcimid.InstanceId)
                                                                                                    New-UDEndpoint -Endpoint {Show-UDToast -Message "$getcimid"} -ArgumentList @($getcimid)
                                                                                                    }

                                                                                                                }
                               
                            New-UDTabContainer -Tabs {
                            
                             New-UDTab -Text 'Server Info'  -Content {                          
	                           New-UDColumn -Size 3 {  
                                                       New-udtable -Title "Average CPU and Mem Utilization" -Headers @("CPU %","Memory %")-Endpoint{ 
                                                       
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
                                                       New-UDTable  -Title "UpTime" -AutoRefresh -Headers @('Last Boot','Uptime') -Endpoint {

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
                                                       New-UDTable -Title "APPD Service Monitoring" -AutoRefresh -Headers @("Name","StartMode","State","Status") -Endpoint {
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
                                                       New-UDTable -Title "Network Details"  -Headers @("IPAddress","SubnetMask","Gateway","DNSServers","MACAddress") -Endpoint {

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
                                                       
                                                       New-UDChart -Title "$servername C Disk Space" -Type Doughnut  -Endpoint {  
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
                                                        


                                                             }
                               New-UDColumn -Size 3 {
                                                        New-UdMonitor -Title "$servername CPU (% processor time)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                                                        Get-Counter -ComputerName $ServerName '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
		                                                     }
                                                        New-UDTable -Title "Top 10 CPU process" -Headers @("Name","PercentProcessorTime") -Endpoint {
                                                       
                                                                gwmi -computername $ServerName Win32_PerfFormattedData_PerfProc_Process -Credential $creds| sort PercentProcessorTime -desc | select Name,PercentProcessorTime | Select -First 10 | Out-UDTableData -Property @("Name","PercentProcessorTime")

                                                       }
                                                       
                                                       }
                               New-UDColumn -Size 3 {  
                                                       New-UDChart -Title "$servername Physical memory Usage" -Type Bar -RefreshInterval 1  -Endpoint {  
                                                                 $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                
                                                                 
                                                                Get-CimInstance -CimSession $session -ClassName win32_operatingsystem   | select -Property TotalVisibleMemorySize, FreePhysicalMemory | ForEach-Object {
                                                                @([PSCustomObject]@{
                                                                                    Label = "Used Memory"
                                                                                    Data = [Math]::Round(($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / 1MB,2);
                                                                                      },
                                                                  [PSCustomObject]@{
                                                                                    Label = "Free Free"
                                                                                    Data = [Math]::Round($_.FreePhysicalMemory / 1MB,2);
                                                                                                                           }) | Out-UDChartData -DataProperty "Data" -LabelProperty "Label" -BackgroundColor @("#80FF6B63","#8028E842") -HoverBackgroundColor @("#80FF6B63","#8028E842") -BorderColor @("#80FF6B63","#8028E842") -HoverBorderColor @("#F2675F","#68e87a")
                                                                                        }
                                                                                       
                                                            
                                                                                                                                 }
                                                       New-UdMonitor -Title "$servername Memory" -Type Line  -RefreshInterval 5 -ChartBackgroundColor @("#80962F23","#8014558C") -ChartBorderColor @('#FFFF6B63','#80962F23' ) -Label @('Commit','Available') -Endpoint { 
                                                       Out-UDMonitorData -Data @(

                                                       Get-Counter -ComputerName $ServerName '\memory\% committed bytes in use'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue  
                                                       Get-Counter -ComputerName $ServerName '\memory\Available Mbytes'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue 
                                                                
                                                                ) 
		                                                     }
                                                       
                                                       New-udtable -Title  "Top 10 Memory process" -Headers @("Name","Private Memory(GB)") -Endpoint {
                                                       
                                                       gwmi -computername $ServerName -Credential $creds Win32_Process | Sort WorkingSetSize -Descending | Select Name,@{n="Private Memory(GB)";Expression = {[math]::round($_.WorkingSetSize / 1GB, 2)}} | Select -First 10 | Out-UDTableData -Property @("Name","Private Memory(GB)")
                                                       
                                                       }
                                                       
                                                       }
                                                       }
                                                                    
                              New-UDTab -Text 'Error Events' -Content {
                             
                                                                      New-UDTable -Title "$servername System error for the past 24 hours"  -Headers @("ProviderName","TimeCreated","Id","LevelDisplayName","Message") -Endpoint {
                                                                      
                                                                      
                                                                                                    $days = (Get-Date).AddHours(-24)


                                                                                                    Get-WinEvent  -ComputerName $servername -Credential $creds -LogName "System"  | Where {$_.TimeCreated -ge $days -and $_.LevelDisplayName -eq "Error"}  | select providername, TimeCreated, Id, LevelDisplayName, Message | Out-UDTableData -Property @("ProviderName","TimeCreated","Id","LevelDisplayName","Message")
                                                                      
                                                                      
                                                                                                                               } 
                                                                     
                                                                     }

                                                       }
		   }
			                                                  
          }
	     }
        }                     
       }
$pages += New-UDPage -Name "Vmware Build" -Content {

New-UDForm -Content {
    New-UDSelect -Id 'type' -Label 'Type' -Option {
        New-UDSelectOption -Name 'Reptile' -Value 1
        New-UDSelectOption -Name 'Mammal' -Value 2
        New-UDSelectOption -Name 'Fish' -Value 3
    } -OnChange {
        Sync-UDElement -Id 'dyAnimal'
    }

    New-UDDynamic -Id 'dyAnimal' -Content {
        $value = (Get-UDElement -Id 'type').value
        Show-UDToast -Message $value

        $Options = @()

        if ($value -eq 1) {
            $Options += New-UDSelectOption -Name 'Snake' -Value 'Snake'
            $Options += New-UDSelectOption -Name 'Gecko' -Value 'Gecko'
            $Options += New-UDSelectOption -Name 'Turtle' -Value 'Turtle'
        } elseif ($value -eq 2) {
            $Options += New-UDSelectOption -Name 'Bear' -Value 'Bear'
            $Options += New-UDSelectOption -Name 'Mountain Lion' -Value 'MountainLion'
            $Options += New-UDSelectOption -Name 'Dog' -Value 'Dog'
        } elseif ($value -eq 3) {
            $Options += New-UDSelectOption -Name 'Pike' -Value 'Pike'
            $Options += New-UDSelectOption -Name 'Catfish' -Value 'Catfish'
            $Options += New-UDSelectOption -Name 'Salmon' -Value 'Salmon'
        } else {
            $Options += New-UDSelectOption -Name 'Select an animal type...' -Value 0
        }

        New-UDSelect -Id 'animal' -Label 'Animal' -Option {
            $Options
        } 
    }
} -OnSubmit {
    Show-UDToast $Body 
}




}
     

     

     
   

   
  
 







$ei = New-UDEndpointInitialization -Module @("C:\Program Files\WindowsPowerShell\Modules\VMware.VimAutomation.Core\10.1.0.8344055\VMware.VimAutomation.Core.psm1")
$Dashboard = New-UDDashboard  -Title 'Server Validation Tool' -Theme $theme  -Page $pages -EndpointInitialization $ei -Footer $footer 
Start-UDDashboard -Port 10001 -Dashboard $Dashboard -Endpoint @($Schedule) 