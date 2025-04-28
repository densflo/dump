

Get-UDDashboard | Stop-UDDashboard

Get-Module -All | Import-Module
Get-PSSession -Name * | Remove-PSSession

$vCenterServer = Get-Content -Path D:\dashboard\vcenter.txt 
Disconnect-VIServer -server $vCenterServer -force -confirm -ErrorAction SilentlyContinue


Set-UDLicense -License (Get-Content -Path C:\inetpub\wwwroot\net472\license.lic)

$CorpDCusername = "corp\inavarrete-a"
$CorpDCpass =  ConvertTo-SecureString -String "I@n@rif121087" -AsPlainText -Force
$Cache:CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass

$vusername = "corp\srvcDev42VC"
$vpass =  ConvertTo-SecureString -String "R#2TwaM@" -AsPlainText -Force
$Cache:Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $vusername,$vpass
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
$null = Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Scope User -InvalidCertificateAction Ignore  -Confirm:$false


$exusername = "srvcExchScripts@corp.ad.tullib.com"
$expass =  ConvertTo-SecureString -String "argwargv312;;" -AsPlainText -Force
$Cache:Credsex = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $exusername,$expass


###
$Every1hour = New-UDEndpointSchedule -Every 1 -Hour
$5minuteschedule = New-UDEndpointSchedule -Every 5 -Minute


$Schedule1 = New-UDEndpoint -Schedule $Every1hour -Endpoint {
    $Cache:EndpointError = $false
    $Cache:vCenterServer = Get-Content -Path D:\dashboard\vcenter.txt 
    if (!($global:DefaultVIServer.Name -eq $Cache:vCenterServer)){
        try{
            
            
            $Cache:VCSession = Connect-VIServer -Server $Cache:vCenterServer -Credential $Cache:Creds -Port 443 -ErrorAction SilentlyContinue
            
        }
        catch{
            $Cache:EndpointError = $_.Exception.Message
        }
    }
    $Cache:ViServerList = $global:DefaultVIServer
}
$DCdiagEndpoint = New-UDEndpoint -Schedule $5minuteschedule -Endpoint {
    $Cache:corpDcDiag = @()
    $Cache:corppath = @()
    $Cache:corppath = Get-ChildItem -Path 'D:\DCdiag\CORP' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:corpDcDiag = Import-Csv -LiteralPath $Cache:corppath
    $Cache:corpDCtitle = $Cache:corppath -replace '.*\\' -replace ",.*"

    $Cache:EURDcDiag = @()
    $Cache:EURpath = @()
    $Cache:EURpath = Get-ChildItem -Path 'D:\DCdiag\EUR' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:EURDcDiag = Import-Csv -LiteralPath $Cache:EURpath

    $Cache:APACDcDiag = @()
    $Cache:APACpath = @()
    $Cache:APACpath = Get-ChildItem -Path 'D:\DCdiag\APAC' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:APACDcDiag = Import-Csv -LiteralPath $Cache:APACpath

    $Cache:NADcDiag = @()
    $Cache:NApath = @()
    $Cache:NApath = Get-ChildItem -Path 'D:\DCdiag\NA' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:NADcDiag = Import-Csv -LiteralPath $Cache:NApath

    $Cache:ROOTADcDiag = @()
    $Cache:ROOTADpath = @()
    $Cache:ROOTADpath = Get-ChildItem -Path 'D:\DCdiag\ROOTAD' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ROOTADDcDiag = Import-Csv -LiteralPath $Cache:ROOTADpath

    $Cache:GLOBALDcDiag = @()
    $Cache:GLOBALpath = @()
    $Cache:GLOBALpath = Get-ChildItem -Path 'D:\DCdiag\GLOBAL' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:GLOBALADDcDiag = Import-Csv -LiteralPath $Cache:GLOBALpath

    $Cache:ICAPROOTDcDiag = @()
    $Cache:ICAPROOTpath = @()
    $Cache:ICAPROOTpath = Get-ChildItem -Path 'D:\DCdiag\ICAPROOT' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ICAPROOTDcDiag = Import-Csv -LiteralPath $Cache:ICAPROOTpath

    $Cache:ICAPDcDiag = @()
    $Cache:ICAPpath = @()
    $Cache:ICAPpath = Get-ChildItem -Path 'D:\DCdiag\ICAP' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ICAPDcDiag = Import-Csv -LiteralPath $Cache:ICAPpath

    $Cache:USDcDiag = @()
    $Cache:USpath = @()
    $Cache:USpath = Get-ChildItem -Path 'D:\DCdiag\US' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:USDcDiag = Import-Csv -LiteralPath $Cache:ICAPpath

    $Cache:CorpDCPing24 = @()
    $Cache:CorpDCPing24 = Import-Csv -Path (Get-ChildItem 'D:\Ping\Corp' -Filter '*.csv').FullName |  Where-Object {$_.investigate -eq 'yes'} |Sort-Object -Property 'Ping Date' -Descending

    
    $Cache:CorpDCPing7 = @()
    $Cache:CorpDCPing7 = Import-Csv -Path (Get-ChildItem 'D:\Ping\Weekly' -Filter '*.csv').FullName |  Where-Object {$_.investigate -eq 'yes'} |Sort-Object -Property 'Ping Date' -Descending

    $Cache:CorpDCPing30 = @()
    $Cache:CorpDCPing30 = Import-Csv -Path (Get-ChildItem 'D:\Ping\Monthly' -Filter '*.csv').FullName |  Where-Object {$_.investigate -eq 'yes'} |Sort-Object -Property 'Ping Date' -Descending

    $Cache:CorpDCPing24Full = @()
    $Cache:CorpDCPing24Full = Import-Csv -Path (Get-ChildItem 'D:\Ping\Corp' -Filter '*.csv').FullName |Sort-Object -Property 'Ping Date' -Descending
    
    $Cache:Link = @()
    $Cache:Link = Import-Csv -Path (Get-ChildItem 'D:\Ping\link' -Filter '*.csv').FullName    
    
             
                        
    
                          
}

  
$footer =  New-UDFooter -Copyright "SVT ver 1.5 2020"  -Links @(
           New-UDLink -Text "Created and Developed by Ian Navarrete" -Url "https://www.linkedin.com/in/ian-n-80172161"
           )
$pages = @()

$pages += New-UDPage -name "SVT" -Content {


New-UDLayout -Columns 1 -Content {

New-UDColumn -SmallSize 3 {
                           
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

New-UDColumn -SmallSize 3 {

                        New-UDInput  -Title "Check File Share Access" -endpoint{param($FilePath) 
                                                              
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {
                                         New-UDTable -Title "$FilePath Access Permission" -AutoRefresh  -Headers @("FileSystemRights","IdentityReference","AccessControlType","Owner") -Endpoint {

                              

                                                    (Get-Acl -path $FilePath).Access | Select  @{N="FileSystemRights";E={[string]$_.FileSystemRights}},@{N="IdentityReference";E={[string ]$_.IdentityReference}},@{N="AccessControlType";E={[string]$_.AccessControlType}},@{Name="Owner";Expression={[string](Get-Acl -path $FilePath).owner}}   | Out-UDTableData -Property @("FileSystemRights","IdentityReference","AccessControlType","Owner")
                                                                    } 

                                                                        
                                            
                                            
                                            

                                         }
                                         }
                                         } -SubmitText "Check"


}

New-UDColumn -SmallSize 3 {

                        New-UDInput  -Title "Check VM status" -endpoint{param($VMStatus) 
                                                              
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {
                                         New-UDTable -Title "$VMStatus Status" -AutoRefresh  -Headers @("Name","PowerState","Num CPUs","MemoryGB") -Endpoint {

                                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                                    Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                                    get-vm -Name $VMStatus -Server * | select @{N="Name";E={[string]$_.Name}},@{N="PowerState";E={[string]$_.PowerState}},@{N="Num CPUs";E={[string]$_.NumCPUs}},@{N="MemoryGB";E={[string]$_.MemoryGB}}  | Out-UDTableData -Property @("Name","PowerState","Num CPUs","MemoryGB")
                                                                    } 

                                                                        
                                            
                                            
                                            

                                         }
                                         }
                                         } -SubmitText "Check"


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
                                                       New-udtable -Title  "$ServerName CPU and Mem Utilization" -AutoRefresh -Headers @("CPU %","Memory %")-Endpoint{ 
                                                       
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
                                                       New-UDTable -Title  "$ServerName UpTime" -AutoRefresh -Headers @('Last Boot','Uptime') -Endpoint {

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
                                                       New-UdMonitor -Title "Disk Perfomance" -Type Line -AutoRefresh -RefreshInterval 5 -ChartBackgroundColor @("#80962F23","#8014558C",'#80FF6B63') -ChartBorderColor @('#FFFF6B63','#80962F23','#82C0CFA' ) -Label @('Avg Disk Queue','Current Disk Queue','Read') -Endpoint { 
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
                                                       New-UDChart -Title "D Disk Space"  -Type Doughnut  -Endpoint {  
                                                           try {
                                                                $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                 
                                                                Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk  | Where-Object {$_.DriveType -eq '3'} | Select-Object -Skip 1 -Property DeviceID,Size,FreeSpace | ForEach-Object {
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
                                                       New-UDTable -Title "$ServerName Drives" -Headers @("Drive","FreeSpace GB","Total Space GB","Free %") -Endpoint {
                                                       Get-WmiObject win32_logicaldisk -ComputerName $Servername -Credential $creds  -ErrorAction SilentlyContinue | Where-Object {$_.DriveType -eq '3'}  | Select-Object deviceID,@{n="FreeSpace";e={ [Math]::truncate($_.FreeSpace / 1GB)}},@{n="size";e={ [Math]::truncate($_.Size / 1GB)}},@{L='Free %';E={($_.FreeSpace/$_.size).tostring("P")}} | Out-UDTableData -Property @("DeviceID","FreeSpace","size","free %")}
                                                       New-UDTable -Title "$ServerName Paging Info" -AutoRefresh -Headers @("Name","Size","PeakUsage GB","CurrentUsage GB") -Endpoint {
                                                                  $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                                    
                                                                                Get-CimInstance -CimSession $session -ClassName win32_pagefileusage | select name,@{n="AllocatedBaseSize GB";Expression = {[math]::round($_.AllocatedBaseSize / 1KB, 2)}},@{n="PeakUsage GB";Expression = {[math]::round($_.PeakUsage / 1KB, 2)}},@{n="CurrentUsage GB";Expression = {[math]::round($_.CurrentUsage / 1KB, 2)}} | Out-UDTableData -Property @("Name","AllocatedBaseSize GB","PeakUsage GB","CurrentUsage GB")



                                                                                 }
                                                        


                                                             }
                               New-UDColumn -Size 3 {
                                                        New-UdMonitor -Title "CPU (% processor time)" -Type Line -DataPointHistory 20 -AutoRefresh -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                                                        Get-Counter -ComputerName $ServerName '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
		                                                     }
                                                        New-UDTable -Title "$ServerName CPU Core Usage" -AutoRefresh -Headers @("Logical Core","Usage %") -Endpoint{

                                                        $res = Get-WmiObject -ComputerName $servername -Credential $creds -Query "select Name, PercentProcessorTime from Win32_PerfFormattedData_PerfOS_Processor" | Where-Object {$_.name -notmatch '_total' } |sort name

                                                        foreach ($single in $res){
                                                                New-Object pscustomobject -Property @{
    
                                                                 cookedvalue = $single.PercentProcessorTime
                                                                 name = $single.Name
                                                                                   } | Out-UDTableData -Property @("Name","cookedvalue")
                                                                   } 

                                                          }
                                                        New-UDTable -Title "$ServerName Top 10 CPU process" -AutoRefresh -Headers @("Name","PercentProcessorTime") -Endpoint {
                                                       
                                                                gwmi -computername $ServerName Win32_PerfFormattedData_PerfProc_Process -Credential $creds|Where-Object {$_.name -notmatch '_total|idle|svchost#'} |sort PercentProcessorTime -desc | select Name,PercentProcessorTime | Select -First 10 | Out-UDTableData -Property @("Name","PercentProcessorTime")

                                                       }
                                                       
                                                       }
                               New-UDColumn -Size 3 {  
                                                       New-UdMonitor -Title "Memory Performance" -Type Line  -AutoRefresh -RefreshInterval 5 -ChartBackgroundColor @("#80962F23","#8014558C",'#80FF6B63') -ChartBorderColor @('#FFFF6B63','#80962F23','#82C0CFA' ) -Label @('Commit','Available','Faults/sec') -Endpoint { 
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
                                                       New-udtable -Title  "$ServerName Top 10 Memory process " -AutoRefresh -Headers @("Name","Private Memory(GB)") -Endpoint {
                                                       
                                                       gwmi -computername $ServerName -Credential $creds Win32_Process | Sort WorkingSetSize -Descending | Select Name,@{n="Private Memory(GB)";Expression = {[math]::round($_.WorkingSetSize / 1GB, 2)}} | Select -First 10 | Out-UDTableData -Property @("Name","Private Memory(GB)")
                                                       
                                                       }
                                                       
                                                       
                                                       }
                                                       }
                                                                    
                             New-UDTab -Text 'Events' -Content {
                                                                      
                                                                      New-UDGrid -Title "$servername System and Application events for past 24 hours" -PageSize 30 -Headers @("ProviderName","TimeCreated","Id","LevelDisplayName","Message") -Properties @("ProviderName","TimeCreated","Id","LevelDisplayName","Message") -Endpoint {
                                                                      
                                                                      
                                                                                                    $days = (Get-Date).AddHours(-24)
                                                                                                    $range = $days.ToShortDateString();


                                                                                          Get-Winevent -ComputerName $servername -Credential $creds -FilterHashtable @{LogName="System","Application"; Level=1,2,3,4; startTime=$range} | select providername, TimeCreated, Id, LevelDisplayName, Message   | Out-UDGridData
                                                                      
                                                                      
                                                                                                                               } 
                                                                     
                                                                     }

                                                       }
		   }
			                                                  
          }
	     }
        }                     
       }
$pages += New-UDPage -Name "Health Check List" -Content {
  
   New-UDTable -Title "Check List" -Headers @("Application","Frequency","Region","Link","Status") -Endpoint {

             $Cache:Link  |%    { 
                    [PSCustomObject]@{
                        Application = $_.application
                        Frequency = $_.Frequency
                        Region = $_.region
                        link = [string]$_.link
                        Status = New-UDSelect  -Option {
                           
                                New-UDSelectOption -Name OK -Value 1
                                New-UDSelectOption -Name Failed -Value 2
                                New-UDSelectOption -Name 'Some Failure' -Value 3     
                            
                        } 
                        
                    }
                } | Out-UDTableData -Property @("Application","Frequency","Region","Link","Status") 
            }

} 
$pages += New-UDPage -name "VMware Morning Checks EMEA" -Content {

              
 New-UDLayout -Columns 1 -Content { 
 New-UDColumn -LargeSize 12 {

                        
                         New-UDCard -Title "EMEA Vcenter Health Details" -TitleAlignment center  -Content {
                               
                                      

                                    }
                         New-UDTabContainer -Tabs {


                           New-UDTab -Text 'ARKPINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 function Check-ESXHost {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
                                                             Get-VMHost -Server ARKPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"ARKPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}}
                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}



                                Check-ESXHost | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate')
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 15% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                                    function Check-Datastore {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
                                                            Get-Datastore -Server ARKPINFVCA01 | Select @{N="Vcenter";E={"ARKPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 15}
                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}
                                    
                                    
                                    Check-Datastore | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    function Check-Snapshot {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
                                                            $vms = get-vm -Server ARKPINFVCA01

                                                            $result =  foreach ($vm in $vms){
                                    
                                                            Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    


                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}

                                    Check-Snapshot | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            function Check-alarmsConfigissues {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
                                                            Get-View -Server ARKPINFVCA01 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} 
                                    


                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}
                    
                            Check-alarmsConfigissues | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            function Check-HostAlarms {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
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


                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}


                           Check-HostAlarms | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           }
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            function Check-HostConfigIssues {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
$HostsViews = Get-View -Server ARKPINFVCA01 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}


                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}

                            Check-HostConfigIssues | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                  function Check-EsxiHardwareIssues {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
 foreach($esx in Get-VMHost){

                                $hs = Get-View -Server ARKPINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}   

}


                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}  

                               

                                          Check-EsxiHardwareIssues   | Out-UDTableData  -Property @('Host','Name','Health') 

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDTable -Title "Alarms $Vcentername"  -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged')  -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


                         function Check-VcenterAlerts {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
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

                           

                             

                            

                             Get-TriggeredAlarms -vCenter ARKPINFVCA01


                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}

                             
                                           Check-VcenterAlerts | Out-UDTableData -Property @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged')
                                  

                              }
                          
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://ARKPINFVCA01/' }
                           }
              
                           }
                           New-UDTab -Text 'LD5PINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LD5PINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LD5PINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 15% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LD5PINFVCA01 | Select @{N="Vcenter";E={"LD5PINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 15} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    $vms = get-vm -Server LD5PINFVCA01

                                    $result =  foreach ($vm in $vms){
                                    
                                     Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    
                                    $result | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            Get-View -Server LD5PINFVCA01 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
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
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                           $HostsViews = Get-View -Server LD5PINFVCA01 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}

$hostcialarms | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
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
                           New-UDButton -text "VMs Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {

        New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
            $VMs = Get-VM -Server LD5PINFVCA01 | Where {$_.PowerState -eq "PoweredOn"}
            New-UDLayout -Columns 3 -Content {
                
                Foreach($VM in $VMs){

                    New-UDcard -Title ($vm.Name) -TextAlignment center -size small -Content {
                        
                        New-UDColumn -Size 6 {
                         New-UDHeading -Text "Memory"           
                         New-UDNivoChart -Id 'MemorChart' -Pie  -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used Memory'
                                value = [int]($vm | Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free Memory'
                                value = [int](100 - ($vm| Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value )
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                       }
                       New-UDColumn -Size 6 {
                         New-UDHeading -text "CPU"           
                         New-UDNivoChart -Id 'CPUChart' -Pie  -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used CPU'
                                value = [int]($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free CPU'
                                value = [int](100 - (($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value))
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                        }


                    }
                }
            }
        }
    }
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -text "Hosts Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {
New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
$null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
$ESXiHostsList = Get-VMHost * -Server LD5PINFVCA01
New-UDLayout -Columns 3 -Content {
Foreach($ESXiHost in $ESXiHostsList){
New-UDcard -Title ($ESXiHost.name) -TextAlignment center -size medium -Content {
New-UDColumn -Size 6 {
New-UDHeading -Text "Memory" 
New-UDNivoChart -Id 'MemoryChart' -Pie -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used Memory'
value = [int]( $ESXiHost | select-object @{N='UsedMemory';E={$_.memoryusageGB / $_.memorytotalGB * 100 }}).usedmemory
}
@{
id = 'Free'
label = 'Free Memory'
value = [int]( $ESXiHost | select-object @{N='FreeMemory';E={100 - ($_.memoryusageGB / $_.memorytotalGB * 100)}}).freememory
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
New-UDColumn -Size 6 {
New-UDHeading -text "CPU" 
New-UDNivoChart -Id 'CPUChart' -Pie -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used CPU'
value = [int]( $ESXiHost | select-object @{N='UsedCPU';E={$_.CpuUsageMhz / $_.CpuTotalMhz * 100 }}).usedCPU
}
@{
id = 'Free'
label = 'Free CPU'
value = [int]( $ESXiHost | select-object @{N='FreeCPU';E={100 - ($_.CpuUsageMhz / $_.CpuTotalMhz * 100)}}).freeCPU
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
}
}
}
}
}
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://LD5PINFVCA01/' }
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
                                New-UDTable  -Title "Datastore Less Than 15% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {

                                    
                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server SYDPINFVCA01 | Select @{N="Vcenter";E={"SYDPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 15} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    $vms = get-vm -Server SYDPINFVCA01

                                    $result =  foreach ($vm in $vms){
                                    
                                     Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    
                                    $result | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            Get-View -Server SYDPINFVCA01 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
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
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                           $HostsViews = Get-View -Server SYDPINFVCA01 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}

$hostcialarms | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
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
                           New-UDButton -text "VMs Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {

        New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
            $VMs = Get-VM -Server SYDPINFVCA01 | Where {$_.PowerState -eq "PoweredOn"}
            New-UDLayout -Columns 3 -Content {
                
                Foreach($VM in $VMs){

                    New-UDcard -Title ($vm.Name) -TextAlignment center -size small -Content {
                        
                        New-UDColumn -Size 6 {
                         New-UDHeading -Text "Memory"           
                         New-UDNivoChart -Id 'MemorChart' -Pie  -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used Memory'
                                value = [int]($vm | Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free Memory'
                                value = [int](100 - ($vm| Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value )
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                       }
                       New-UDColumn -Size 6 {
                         New-UDHeading -text "CPU"           
                         New-UDNivoChart -Id 'CPUChart' -Pie  -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used CPU'
                                value = [int]($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free CPU'
                                value = [int](100 - (($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value))
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                        }


                    }
                }
            }
        }
    }
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -text "Hosts Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {
New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
$null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
$ESXiHostsList = Get-VMHost * -Server SYDPINFVCA01
New-UDLayout -Columns 3 -Content {
Foreach($ESXiHost in $ESXiHostsList){
New-UDcard -Title ($ESXiHost.name) -TextAlignment center -size medium -Content {
New-UDColumn -Size 6 {
New-UDHeading -Text "Memory" 
New-UDNivoChart -Id 'MemoryChart' -Pie -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used Memory'
value = [int]( $ESXiHost | select-object @{N='UsedMemory';E={$_.memoryusageGB / $_.memorytotalGB * 100 }}).usedmemory
}
@{
id = 'Free'
label = 'Free Memory'
value = [int]( $ESXiHost | select-object @{N='FreeMemory';E={100 - ($_.memoryusageGB / $_.memorytotalGB * 100)}}).freememory
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
New-UDColumn -Size 6 {
New-UDHeading -text "CPU" 
New-UDNivoChart -Id 'CPUChart' -Pie -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used CPU'
value = [int]( $ESXiHost | select-object @{N='UsedCPU';E={$_.CpuUsageMhz / $_.CpuTotalMhz * 100 }}).usedCPU
}
@{
id = 'Free'
label = 'Free CPU'
value = [int]( $ESXiHost | select-object @{N='FreeCPU';E={100 - ($_.CpuUsageMhz / $_.CpuTotalMhz * 100)}}).freeCPU
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
}
}
}
}
}
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://SYDPINFVCA01/' }
                           }
              
                           }
                           New-UDTab -Text 'SYDPINFVCA02'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server SYDPINFVCA02 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SYDPINFVCA02"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 15% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server SYDPINFVCA02 | Select @{N="Vcenter";E={"SYDPINFVCA02"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 15} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    $vms = get-vm -Server SYDPINFVCA02

                                    $result =  foreach ($vm in $vms){
                                    
                                     Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    
                                    $result | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            Get-View -Server SYDPINFVCA02 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
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
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                           $HostsViews = Get-View -Server SYDPINFVCA02 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}

$hostcialarms | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
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
                           New-UDButton -text "VMs Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {

        New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
            $VMs = Get-VM -Server SYDPINFVCA02 | Where {$_.PowerState -eq "PoweredOn"}
            New-UDLayout -Columns 3 -Content {
                
                Foreach($VM in $VMs){

                    New-UDcard -Title ($vm.Name) -TextAlignment center -size small -Content {
                        
                        New-UDColumn -Size 6 {
                         New-UDHeading -Text "Memory"           
                         New-UDNivoChart -Id 'MemorChart' -Pie  -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used Memory'
                                value = [int]($vm | Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free Memory'
                                value = [int](100 - ($vm| Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value )
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                       }
                       New-UDColumn -Size 6 {
                         New-UDHeading -text "CPU"           
                         New-UDNivoChart -Id 'CPUChart' -Pie  -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used CPU'
                                value = [int]($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free CPU'
                                value = [int](100 - (($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value))
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                        }


                    }
                }
            }
        }
    }
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -text "Hosts Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {
New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
$null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
$ESXiHostsList = Get-VMHost * -Server SYDPINFVCA02
New-UDLayout -Columns 3 -Content {
Foreach($ESXiHost in $ESXiHostsList){
New-UDcard -Title ($ESXiHost.name) -TextAlignment center -size medium -Content {
New-UDColumn -Size 6 {
New-UDHeading -Text "Memory" 
New-UDNivoChart -Id 'MemoryChart' -Pie -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used Memory'
value = [int]( $ESXiHost | select-object @{N='UsedMemory';E={$_.memoryusageGB / $_.memorytotalGB * 100 }}).usedmemory
}
@{
id = 'Free'
label = 'Free Memory'
value = [int]( $ESXiHost | select-object @{N='FreeMemory';E={100 - ($_.memoryusageGB / $_.memorytotalGB * 100)}}).freememory
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
New-UDColumn -Size 6 {
New-UDHeading -text "CPU" 
New-UDNivoChart -Id 'CPUChart' -Pie -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used CPU'
value = [int]( $ESXiHost | select-object @{N='UsedCPU';E={$_.CpuUsageMhz / $_.CpuTotalMhz * 100 }}).usedCPU
}
@{
id = 'Free'
label = 'Free CPU'
value = [int]( $ESXiHost | select-object @{N='FreeCPU';E={100 - ($_.CpuUsageMhz / $_.CpuTotalMhz * 100)}}).freeCPU
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
}
}
}
}
}
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://SYDPINFVCA02/' }
                           }
              
                           }
                           New-UDTab -Text 'SNGPINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server SNGPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SNGPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 15% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server SNGPINFVCA01 | Select @{N="Vcenter";E={"SNGPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 15} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    $vms = get-vm -Server SNGPINFVCA01

                                    $result =  foreach ($vm in $vms){
                                    
                                     Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    
                                    $result | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }

                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            Get-View -Server SNGPINFVCA01 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
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
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                           $HostsViews = Get-View -Server SNGPINFVCA01 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}

$hostcialarms | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
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
                           New-UDButton -text "VMs Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {

        New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
            $VMs = Get-VM -Server SNGPINFVCA01 | Where {$_.PowerState -eq "PoweredOn"}
            New-UDLayout -Columns 3 -Content {
                
                Foreach($VM in $VMs){

                    New-UDcard -Title ($vm.Name) -TextAlignment center -size small -Content {
                        
                        New-UDColumn -Size 6 {
                         New-UDHeading -Text "Memory"           
                         New-UDNivoChart -Id 'MemorChart' -Pie  -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used Memory'
                                value = [int]($vm | Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free Memory'
                                value = [int](100 - ($vm| Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value )
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                       }
                       New-UDColumn -Size 6 {
                         New-UDHeading -text "CPU"           
                         New-UDNivoChart -Id 'CPUChart' -Pie  -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used CPU'
                                value = [int]($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free CPU'
                                value = [int](100 - (($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value))
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                        }


                    }
                }
            }
        }
    }
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -text "Hosts Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {
New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
$null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
$ESXiHostsList = Get-VMHost * -Server SNGPINFVCA01
New-UDLayout -Columns 3 -Content {
Foreach($ESXiHost in $ESXiHostsList){
New-UDcard -Title ($ESXiHost.name) -TextAlignment center -size medium -Content {
New-UDColumn -Size 6 {
New-UDHeading -Text "Memory" 
New-UDNivoChart -Id 'MemoryChart' -Pie -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used Memory'
value = [int]( $ESXiHost | select-object @{N='UsedMemory';E={$_.memoryusageGB / $_.memorytotalGB * 100 }}).usedmemory
}
@{
id = 'Free'
label = 'Free Memory'
value = [int]( $ESXiHost | select-object @{N='FreeMemory';E={100 - ($_.memoryusageGB / $_.memorytotalGB * 100)}}).freememory
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
New-UDColumn -Size 6 {
New-UDHeading -text "CPU" 
New-UDNivoChart -Id 'CPUChart' -Pie -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used CPU'
value = [int]( $ESXiHost | select-object @{N='UsedCPU';E={$_.CpuUsageMhz / $_.CpuTotalMhz * 100 }}).usedCPU
}
@{
id = 'Free'
label = 'Free CPU'
value = [int]( $ESXiHost | select-object @{N='FreeCPU';E={100 - ($_.CpuUsageMhz / $_.CpuTotalMhz * 100)}}).freeCPU
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
}
}
}
}
}
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://SNGPINFVCA01/' }
                           }
              
                           }
                           New-UDTab -Text 'SNG2VA0001'        -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server SNG2VA0001 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SNGPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 15% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server SNG2VA0001 | Select @{N="Vcenter";E={"SNGPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 15} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    $vms = get-vm -Server SNG2VA0001

                                    $result =  foreach ($vm in $vms){
                                    
                                     Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    
                                    $result | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }

                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            Get-View -Server SNG2VA0001 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server SNG2VA0001 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
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
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                           $HostsViews = Get-View -Server SNG2VA0001 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}

$hostcialarms | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server SNG2VA0001 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

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

                             $vcenteralarm = Get-TriggeredAlarms -vCenter SNG2VA0001

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }
                           New-UDButton -text "VMs Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {

        New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
            $VMs = Get-VM -Server SNG2VA0001 | Where {$_.PowerState -eq "PoweredOn"}
            New-UDLayout -Columns 3 -Content {
                
                Foreach($VM in $VMs){

                    New-UDcard -Title ($vm.Name) -TextAlignment center -size small -Content {
                        
                        New-UDColumn -Size 6 {
                         New-UDHeading -Text "Memory"           
                         New-UDNivoChart -Id 'MemorChart' -Pie  -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used Memory'
                                value = [int]($vm | Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free Memory'
                                value = [int](100 - ($vm| Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value )
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                       }
                       New-UDColumn -Size 6 {
                         New-UDHeading -text "CPU"           
                         New-UDNivoChart -Id 'CPUChart' -Pie  -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used CPU'
                                value = [int]($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free CPU'
                                value = [int](100 - (($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value))
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                        }


                    }
                }
            }
        }
    }
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -text "Hosts Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {
New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
$null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
$ESXiHostsList = Get-VMHost * -Server SNG2VA0001
New-UDLayout -Columns 3 -Content {
Foreach($ESXiHost in $ESXiHostsList){
New-UDcard -Title ($ESXiHost.name) -TextAlignment center -size medium -Content {
New-UDColumn -Size 6 {
New-UDHeading -Text "Memory" 
New-UDNivoChart -Id 'MemoryChart' -Pie -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used Memory'
value = [int]( $ESXiHost | select-object @{N='UsedMemory';E={$_.memoryusageGB / $_.memorytotalGB * 100 }}).usedmemory
}
@{
id = 'Free'
label = 'Free Memory'
value = [int]( $ESXiHost | select-object @{N='FreeMemory';E={100 - ($_.memoryusageGB / $_.memorytotalGB * 100)}}).freememory
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
New-UDColumn -Size 6 {
New-UDHeading -text "CPU" 
New-UDNivoChart -Id 'CPUChart' -Pie -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used CPU'
value = [int]( $ESXiHost | select-object @{N='UsedCPU';E={$_.CpuUsageMhz / $_.CpuTotalMhz * 100 }}).usedCPU
}
@{
id = 'Free'
label = 'Free CPU'
value = [int]( $ESXiHost | select-object @{N='FreeCPU';E={100 - ($_.CpuUsageMhz / $_.CpuTotalMhz * 100)}}).freeCPU
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
}
}
}
}
}
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://SNG2VA0001/' }
                           }
              
                           }
                           New-UDTab -Text 'SNG1VA0001'        -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server SNG1VA0001 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"SNGPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 15% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server SNG1VA0001 | Select @{N="Vcenter";E={"SNGPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 15} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    $vms = get-vm -Server SNG1VA0001

                                    $result =  foreach ($vm in $vms){
                                    
                                     Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    
                                    $result | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }

                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            Get-View -Server SNG1VA0001 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server SNG1VA0001 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
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
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                           $HostsViews = Get-View -Server SNG1VA0001 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}

$hostcialarms | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server SNG1VA0001 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

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

                             $vcenteralarm = Get-TriggeredAlarms -vCenter SNG1VA0001

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }
                           New-UDButton -text "VMs Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {

        New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
            $VMs = Get-VM -Server SNG1VA0001 | Where {$_.PowerState -eq "PoweredOn"}
            New-UDLayout -Columns 3 -Content {
                
                Foreach($VM in $VMs){

                    New-UDcard -Title ($vm.Name) -TextAlignment center -size small -Content {
                        
                        New-UDColumn -Size 6 {
                         New-UDHeading -Text "Memory"           
                         New-UDNivoChart -Id 'MemorChart' -Pie  -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used Memory'
                                value = [int]($vm | Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free Memory'
                                value = [int](100 - ($vm| Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value )
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                       }
                       New-UDColumn -Size 6 {
                         New-UDHeading -text "CPU"           
                         New-UDNivoChart -Id 'CPUChart' -Pie  -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used CPU'
                                value = [int]($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free CPU'
                                value = [int](100 - (($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value))
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                        }


                    }
                }
            }
        }
    }
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -text "Hosts Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {
New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
$null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
$ESXiHostsList = Get-VMHost * -Server SNG1VA0001
New-UDLayout -Columns 3 -Content {
Foreach($ESXiHost in $ESXiHostsList){
New-UDcard -Title ($ESXiHost.name) -TextAlignment center -size medium -Content {
New-UDColumn -Size 6 {
New-UDHeading -Text "Memory" 
New-UDNivoChart -Id 'MemoryChart' -Pie -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used Memory'
value = [int]( $ESXiHost | select-object @{N='UsedMemory';E={$_.memoryusageGB / $_.memorytotalGB * 100 }}).usedmemory
}
@{
id = 'Free'
label = 'Free Memory'
value = [int]( $ESXiHost | select-object @{N='FreeMemory';E={100 - ($_.memoryusageGB / $_.memorytotalGB * 100)}}).freememory
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
New-UDColumn -Size 6 {
New-UDHeading -text "CPU" 
New-UDNivoChart -Id 'CPUChart' -Pie -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used CPU'
value = [int]( $ESXiHost | select-object @{N='UsedCPU';E={$_.CpuUsageMhz / $_.CpuTotalMhz * 100 }}).usedCPU
}
@{
id = 'Free'
label = 'Free CPU'
value = [int]( $ESXiHost | select-object @{N='FreeCPU';E={100 - ($_.CpuUsageMhz / $_.CpuTotalMhz * 100)}}).freeCPU
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
}
}
}
}
}
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://SNG1VA0001/' }
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
                                New-UDTable  -Title "Datastore Less Than 15% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server njcesxvsvc01 | Select @{N="Vcenter";E={"njcesxvsvc01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 15} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    $vms = get-vm -Server njcesxvsvc01

                                    $result =  foreach ($vm in $vms){
                                    
                                     Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    
                                    $result | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            Get-View -Server njcesxvsvc01 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
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
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                           $HostsViews = Get-View -Server njcesxvsvc01 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}

$hostcialarms | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
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
                           New-UDButton -text "VMs Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {

        New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
            $VMs = Get-VM -Server njcesxvsvc01 | Where {$_.PowerState -eq "PoweredOn"}
            New-UDLayout -Columns 3 -Content {
                
                Foreach($VM in $VMs){

                    New-UDcard -Title ($vm.Name) -TextAlignment center -size small -Content {
                        
                        New-UDColumn -Size 6 {
                         New-UDHeading -Text "Memory"           
                         New-UDNivoChart -Id 'MemorChart' -Pie  -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used Memory'
                                value = [int]($vm | Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free Memory'
                                value = [int](100 - ($vm| Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value )
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                       }
                       New-UDColumn -Size 6 {
                         New-UDHeading -text "CPU"           
                         New-UDNivoChart -Id 'CPUChart' -Pie  -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used CPU'
                                value = [int]($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free CPU'
                                value = [int](100 - (($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value))
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                        }


                    }
                }
            }
        }
    }
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -text "Hosts Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {
New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
$null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
$ESXiHostsList = Get-VMHost * -Server njcesxvsvc01
New-UDLayout -Columns 3 -Content {
Foreach($ESXiHost in $ESXiHostsList){
New-UDcard -Title ($ESXiHost.name) -TextAlignment center -size medium -Content {
New-UDColumn -Size 6 {
New-UDHeading -Text "Memory" 
New-UDNivoChart -Id 'MemoryChart' -Pie -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used Memory'
value = [int]( $ESXiHost | select-object @{N='UsedMemory';E={$_.memoryusageGB / $_.memorytotalGB * 100 }}).usedmemory
}
@{
id = 'Free'
label = 'Free Memory'
value = [int]( $ESXiHost | select-object @{N='FreeMemory';E={100 - ($_.memoryusageGB / $_.memorytotalGB * 100)}}).freememory
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
New-UDColumn -Size 6 {
New-UDHeading -text "CPU" 
New-UDNivoChart -Id 'CPUChart' -Pie -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used CPU'
value = [int]( $ESXiHost | select-object @{N='UsedCPU';E={$_.CpuUsageMhz / $_.CpuTotalMhz * 100 }}).usedCPU
}
@{
id = 'Free'
label = 'Free CPU'
value = [int]( $ESXiHost | select-object @{N='FreeCPU';E={100 - ($_.CpuUsageMhz / $_.CpuTotalMhz * 100)}}).freeCPU
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
}
}
}
}
}
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://njcesxvsvc01/' }
                           }
              
                           }
                           

                           }
                    }


                            
               }

}   
$pages += New-UDPage -name "Exchange Internal Health" -Content {
New-UDTabContainer -Tabs {
New-UDTab -Text 'Overview'                   -Content {
New-UDLayout -Columns 2 {

         New-UDColumn -Size 12 {  
                                                       
                                                       
New-UDTable -Title  "Last successful Mailbox Database Backup" -Headers @('Name','LastFullBackup') -Endpoint {

                                                       function check-exchange {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 



<#################################################################
#          Last successful Mailbox Database Backup               # 
##################################################################>
Get-MailboxDatabase -includepreexchange2013 -status | Select-Object Name, LastFullBackup | Sort-Object LastFullBackup 




  }
end {
  Remove-PSSession -Session $exSession
 }
}

                                                       check-exchange | select Name,LastFullBackup  | Out-UDTableData -Property @("Name","LastFullBackup")
                                                       
                                                               }
New-UDTable -Title  "Exchange (Windows) Service Health" -Headers @("MachineName","DisplayName","Status") -Endpoint {

                                                       function Check-ExchangeHealthService {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 


<#################################################################
#              Exchange (Windows) Service Health                 # 
##################################################################>
$UnhealthyWindowsServices = @()

$ExchangeServers =  $(Get-MailboxServer | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyWindowsServices += Get-Service -Name MSExchange* -ComputerName $objExchangeServer | Where-Object {($_.Name -ne "MSExchangeNotificationsBroker") -and ($_.Status -ne "Running")}
}

$UnhealthyWindowsServices 




  }
end {
  Remove-PSSession -Session $exSession
 }
}

Check-ExchangeHealthService | Sort-Object MachineName | select MachineName, DisplayName, @{N="Status";E={[string]$_.Status}} -First 5 | Out-UDTableData -Property @("MachineName","DisplayName","status")
                     
                                                               }
New-UDTable -Title  "Mailbox Database Copy Health" -Headers  @("Name","Status","InstanceStartTime","InternalStartupMessage","MailboxServer","ContentIndexState") -Endpoint {

                                                       
function Copy-DatabasHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



}  
process { 


<#################################################################
#                  Mailbox Database Copy Health                  # 
##################################################################>
$UnhealthyDatabases = @()

$ExchangeServers =  $(Get-MailboxServer  | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyDatabases += Get-MailboxDatabaseCopyStatus -Server $objExchangeServer   | Where-Object {($_.Status -ne "Healthy") -and ($_.Status -ne "Mounted")} -ErrorAction SilentlyContinue
}

$UnhealthyDatabases | Sort-Object Name




  }
end {
  Remove-PSSession -Session $exSession
 }
}

Copy-DatabasHealth | select Name,Status,InstanceStartTime,InternalStartupMessage,MailboxServer,ContentIndexState -First 5  | Out-UDTableData -Property @("Name","Status","InstanceStartTime","InternalStartupMessage","MailboxServer","ContentIndexState")

                                                               }
New-UDTable -Title  "HTTPS Service Health (OWA / ECP / Autodiscover etc)" -Headers  @("StatusCode","StatusDescription","URL") -Endpoint {

                                                       

function Http-ServiceHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex 
Import-PSSession $exSession -DisableNameChecking -AllowClobber 
 


}  
process { 

<#################################################################
#     HTTPS Service Health (OWA / ECP / Autodiscover etc)        # 
##################################################################>
$ExchangeServers =  $(Get-MailboxServer | Sort-Object Name).Name

$HealthChecks = @(
    "/autodiscover/healthcheck.htm",
    "/mapi/healthcheck.htm",
    "/rpc/healthcheck.htm",
    "/oab/healthcheck.htm",
    "/owa/healthcheck.htm",
    "/ecp/healthcheck.htm",
    "/ews/healthcheck.htm",
    "/microsoft-server-activesync/healthcheck.htm"
)

$UnhealthyWebServices = @()

Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


ForEach ($objExchangeServer in $ExchangeServers){
        
        ForEach ($objHealthCheck in $Healthchecks){
            $UnhealthyWebServices += Invoke-WebRequest -Uri "https://$objExchangeServer.corp.ad.tullib.com$objHealthCheck" -UseBasicParsing | Where-Object {$_.StatusCode -ne "200"} -ErrorAction SilentlyContinue
        }
}

$UnhealthyWebServices




  }
end {
  Remove-PSSession -Session $exSession
 }
}

Http-ServiceHealth -ErrorAction SilentlyContinue | select StatusCode,StatusDescription,@{N="URL";E={[string]$_.BaseResponse.ResponseUri.OriginalString}}   | Out-UDTableData -Property @("StatusCode","StatusDescription","URL")

                                                               }
                                                           
                                                                    }
         New-UDColumn -LargeSize 12 {  
                                                       
New-UDTable -Title  "Mailbox Database Index Health" -Headers  @("DatabaseName","MailboxServer","ContentIndexState") -Endpoint {

                                                       function Check-DatabaseIndex {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 
<#################################################################
#                  Mailbox Database Index Health                 # 
##################################################################>

$UnhealthyIndexes = @()

$ExchangeServers =  $(Get-MailboxServer).name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyIndexes += Get-MailboxDatabaseCopyStatus -Server $objExchangeServer | Where-Object {$_.ContentIndexState -ne "Healthy"}
}

$UnhealthyIndexes |select "DatabaseName","MailboxServer","ContentIndexState" 

 }
end {
  Remove-PSSession -Session $exSession
 }
}

Check-DatabaseIndex | select DatabaseName,MailboxServer,ContentIndexState | Out-UDTableData -Property @("DatabaseName","MailboxServer","ContentIndexState")
                        
}                                                       
New-UDTable -Title  "SMTP Service Health" -Headers  @("ComputerName","RemotePort","RemoteAddress","PingSucceeded","TcpTestSucceeded") -Endpoint {

                                                       function Smtp-ExchangeHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 


<#################################################################
#     	               SMTP Service Health                       # 
##################################################################>
$UnhealthySMTP = @()

$ExchangeServers =  $(Get-MailboxServer  | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthySMTP += Test-NetConnection $objExchangeServer -Port 25 -ErrorAction Ignore | Where-Object {$_.TcpTestSucceeded -ne "True"}
}

$UnhealthySMTP 




  }
end {
  Remove-PSSession -Session $exSession
 }
}

Smtp-ExchangeHealth |Sort-Object ComputerName | select ComputerName,RemotePort,@{N="RemoteAddress";E={[string]$_.RemoteAddress}},@{N="PingSucceeded";E={[string]$_.PingSucceeded}},@{N="TcpTestSucceeded";E={[string]$_.TcpTestSucceeded}}   | Out-UDTableData -Property @("ComputerName","RemotePort","RemoteAddress","PingSucceeded","TcpTestSucceeded")
                         
                                                               }
New-UDTable -Title  "POP3 Service Health" -Headers  @("ComputerName","RemotePort","RemoteAddress","PingSucceeded","TcpTestSucceeded") -Endpoint {

                                                       
function POP3-ServiceHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 


<#################################################################
#     	               POP3 Service Health                       # 
##################################################################>
$UnhealthyPOP = @()

$ExchangeServers =  $(Get-MailboxServer | Sort-Object Name).Name 

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyPOP += Test-NetConnection $objExchangeServer -Port 110 | Where-Object {$_.TcpTestSucceeded -ne "True"}
}

$UnhealthyPOP 



  }
end {
  Remove-PSSession -Session $exSession
 }
}

POP3-ServiceHealth |Sort-Object ComputerName | select ComputerName,RemotePort,@{N="RemoteAddress";E={[string]$_.RemoteAddress}},@{N="PingSucceeded";E={[string]$_.PingSucceeded}},@{N="TcpTestSucceeded";E={[string]$_.TcpTestSucceeded}} | Out-UDTableData -Property @("ComputerName","RemotePort","RemoteAddress","PingSucceeded","TcpTestSucceeded")
                       
                                                               }
New-UDTable -Title  "IMAP Service Health" -Headers  @("ComputerName","RemotePort","RemoteAddress","PingSucceeded","TcpTestSucceeded") -Endpoint {

                                                       
function Imap-ServiceHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 


<#################################################################
#     	               IMAP Service Health                       # 
##################################################################>
$UnhealthyIMAP = @()

$ExchangeServers =  $(Get-MailboxServer  | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyIMAP += Test-NetConnection $objExchangeServer -Port 143 | Where-Object {$_.TcpTestSucceeded -ne "True"}
}

$UnhealthyIMAP |Sort-Object ComputerName 



  }
end {
  Remove-PSSession -Session $exSession
 }
}

Imap-ServiceHealth |Sort-Object ComputerName | select ComputerName,RemotePort,@{N="RemoteAddress";E={[string]$_.RemoteAddress}},@{N="PingSucceeded";E={[string]$_.PingSucceeded}},@{N="TcpTestSucceeded";E={[string]$_.TcpTestSucceeded}} | Out-UDTableData -Property @("ComputerName","RemotePort","RemoteAddress","PingSucceeded","TcpTestSucceeded")
                        
                                                               }
New-UDTable -Title  "Mail Queue Health"   -Headers  @("QueueIdentity","DeliveryType","Status","MessageCount","NextHopDomain") -Endpoint {

function check-exchangeMailQueue {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 



<#################################################################
#          Mal Queue            # 
##################################################################>


$ExchangeServers =  $(Get-transportServer  | Sort-Object Name).Name


    $stats_collection = $ExchangeServers | Sort-Object Name | ForEach-Object { Get-Queue -Server $_ -ErrorAction SilentlyContinue  | Where-Object { $_.Identity -notmatch 'Shadow' -and $_.Identity -notmatch 'unreachable'}  }
    
    return $stats_collection 







  }
end {
  Remove-PSSession -Session $exSession
 }
}

check-exchangeMailQueue | select QueueIdentity,DeliveryType,Status,MessageCount,NextHopDomain | Out-UDTableData -Property @("QueueIdentity","DeliveryType","Status","MessageCount","NextHopDomain")

}

                                                       
                                                           
                                                                    } 
  
  
  }
New-UDLayout -Columns 1 {

New-UDTable -Title  "General Exchange Health" -Headers @("Server","CurrentHealthSetState","Name","TargetResource","HealthSetName","HealthGroupName","AlertValue","FirstAlertObservedTime","Description","DefinitionCreatedTime") -Endpoint {

                                                       function General-ExchangeHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 


<#################################################################
#                   General Exchange Health                      # 
##################################################################>
Get-MailboxServer  | Get-ServerHealth | Where-Object {($_.AlertValue -ne "Healthy") -and ($_.AlertValue -ne "Disabled") -and ($_.name  -ne "*tmp_*")} 




  }
end {
  Remove-PSSession -Session $exSession
 }
}

General-ExchangeHealth | select Server,CurrentHealthSetState,Name,TargetResource,HealthSetName,HealthGroupName,AlertValue,FirstAlertObservedTime,Description,DefinitionCreatedTime | Out-UDTableData -Property @("Server","CurrentHealthSetState","Name","TargetResource","HealthSetName","HealthGroupName","AlertValue","FirstAlertObservedTime","Description","DefinitionCreatedTime")
                        
                                                               }

}
  }
New-UDTab -Text 'Exchange Server Status'     -Content {

New-UDGrid -Title "General Exchange Health" -Headers @("Server","CurrentHealthSetState","Name","TargetResource","HealthSetName","HealthGroupName","AlertValue","FirstAlertObservedTime","Description","DefinitionCreatedTime") -Properties @("Server","CurrentHealthSetState","Name","TargetResource","HealthSetName","HealthGroupName","AlertValue","FirstAlertObservedTime","Description","DefinitionCreatedTime") -PageSize 100 -DefaultSortColumn "CurrentHealthSetState" -Endpoint {

function General-ExchangeHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 


<#################################################################
#                   General Exchange Health                      # 
##################################################################>
Get-MailboxServer | Get-ServerHealth 




  }
end {
  Remove-PSSession -Session $exSession
 }
}

General-ExchangeHealth | select Server,CurrentHealthSetState,Name,TargetResource,HealthSetName,HealthGroupName,AlertValue,FirstAlertObservedTime,Description,DefinitionCreatedTime | Out-UDGridData


  }
 }
New-UDTab -Text 'Mailbox Database Copy'      -Content {

New-UDGrid -Title "Mailbox Database Copy Health" -Headers  @("Name","Status","InstanceStartTime","InternalStartupMessage","MailboxServer","ContentIndexState") -Properties @("Name","Status","InstanceStartTime","InternalStartupMessage","MailboxServer","ContentIndexState") -PageSize 100 -DefaultSortColumn "status" -Endpoint {

function Copy-DatabasHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



}  
process { 


<#################################################################
#                  Mailbox Database Copy Health                  # 
##################################################################>
$UnhealthyDatabases = @()

$ExchangeServers =  $(Get-MailboxServer  | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyDatabases += Get-MailboxDatabaseCopyStatus -Server $objExchangeServer 
}

$UnhealthyDatabases | Sort-Object Name




  }
end {
  Remove-PSSession -Session $exSession
 }
}

Copy-DatabasHealth | select Name,Status,InstanceStartTime,InternalStartupMessage,MailboxServer,ContentIndexState  | Out-UDGridData

}

}
New-UDTab -Text 'Exchange Queue Lenghts'     -Content {

New-UDGrid -Title "Exchange Queue" -Headers  @("QueueIdentity","DeliveryType","Status","MessageCount","NextHopDomain") -Properties @("QueueIdentity","DeliveryType","Status","MessageCount","NextHopDomain") -PageSize 100 -DefaultSortColumn "status" -Endpoint{


function check-exchangeMailQueue {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 



<#################################################################
#          Mal Queue            # 
##################################################################>


$ExchangeServers =  $(Get-transportServer  | Sort-Object Name).Name


    $stats_collection = $ExchangeServers | Sort-Object Name | ForEach-Object { Get-Queue -Server $_ -ErrorAction SilentlyContinue  | Where-Object { $_.Identity -notmatch 'Shadow' -and $_.Identity -notmatch 'unreachable'}  }
    
    return $stats_collection 







  }
end {
  Remove-PSSession -Session $exSession
 }
}

check-exchangeMailQueue | select QueueIdentity,DeliveryType,Status,MessageCount,NextHopDomain | Out-UDGridData


 }

}
New-UDTab -Text 'Exchange Windows Services'  -Content {

New-UDGrid -Title "Exchange (Windows) Service Health" -Headers @("MachineName","DisplayName","Status") -Properties @("MachineName","DisplayName","Status") -PageSize 100 -DefaultSortColumn "Status" -Endpoint {

function Check-ExchangeHealthService {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 


<#################################################################
#              Exchange (Windows) Service Health                 # 
##################################################################>
$UnhealthyWindowsServices = @()

$ExchangeServers =  $(Get-MailboxServer  | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthyWindowsServices += Get-Service -Name MSExchange* -ComputerName $objExchangeServer 
}

$UnhealthyWindowsServices 




  }
end {
  Remove-PSSession -Session $exSession
 }
}

Check-ExchangeHealthService | Sort-Object MachineName | select MachineName, DisplayName, @{N="Status";E={[string]$_.Status}} | Out-UDGridData
 
}
New-UDTab -Text 'Mailbox datastore backup'  -Content {}
New-UDTab -Text 'SMTP'  -Content {}

 }
New-UDTab -Text 'Mailbox datastore backup'   -Content {

New-UDGrid -Title "Mailbox Database Backup" -Headers @('Name','LastFullBackup') -Properties @('Name','LastFullBackup') -PageSize 100 -DefaultSortColumn "lastfullbackup" -Endpoint {


                                                       function check-exchange {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



}  
process { 



<#################################################################
#          Last successful Mailbox Database Backup               # 
##################################################################>
Get-MailboxDatabase -Includepreexchange2013 -Status | Select-Object Name, LastFullBackup | Sort-Object LastFullBackup




  }
end {
  Remove-PSSession -Session $exSession
 }
}

                                                      check-exchange | select Name,LastFullBackup  | Out-UDGridData
                                                       
 }
}
New-UDTab -Text 'SMTP'                       -Content {

New-UDGrid -Title "SMTP Service Health" -Headers @("ComputerName","RemotePort","RemoteAddress","PingSucceeded","TcpTestSucceeded") -Properties @("ComputerName","RemotePort","RemoteAddress","PingSucceeded","TcpTestSucceeded") -PageSize 100 -DefaultSortDescending -Endpoint {
function Smtp-ExchangeHealth {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


$exSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://LDN1WS9642.corp.ad.tullib.com/PowerShell/ -Authentication Kerberos -Credential $Cache:Credsex
Import-PSSession $exSession -DisableNameChecking -AllowClobber 



} 
process { 


<#################################################################
#     	               SMTP Service Health                       # 
##################################################################>
$UnhealthySMTP = @()

$ExchangeServers =  $(Get-MailboxServer | Sort-Object Name).Name

ForEach ($objExchangeServer in $ExchangeServers){
        $UnhealthySMTP += Test-NetConnection $objExchangeServer -Port 25 -ErrorAction Ignore
}

$UnhealthySMTP 




  }
end {
  Remove-PSSession -Session $exSession
 }
}

Smtp-ExchangeHealth |Sort-Object ComputerName | select ComputerName,RemotePort,@{N="RemoteAddress";E={[string]$_.RemoteAddress}},@{N="PingSucceeded";E={[string]$_.PingSucceeded}},@{N="TcpTestSucceeded";E={[string]$_.TcpTestSucceeded}}   | Out-UDGridData

 }



}

 }
}
$pages += New-UDPage -name "DCdiag" -Content {

New-UDLayout -Columns 1 -Content {
New-UDTabContainer -Tabs {
New-UDTab -Text 'DC Diag Morning Check' -Content {
New-UDColumn -Size 3 {
New-UDTable -Title 'DC Diag CSV files' -Headers @(" "," ") -Endpoint {

$corpcsv = $Cache:corppath -replace '.*\\' -replace ",.*"
$EURcsv = $Cache:EURpath -replace '.*\\' -replace ",.*"
$APACcsv = $Cache:APACpath -replace '.*\\' -replace ",.*"
$NAcsv = $Cache:NApath -replace '.*\\' -replace ",.*"
$ROOTADcsv = $Cache:ROOTADpath -replace '.*\\' -replace ",.*"
$Globalcsv = $Cache:GLOBALpath -replace '.*\\' -replace ",.*"
$ICAPROOTcsv = $Cache:ICAPROOTpath -replace '.*\\' -replace ",.*"
$ICAPcsv = $Cache:ICAPpath -replace '.*\\' -replace ",.*"
$UScsv = $Cache:USpath -replace '.*\\' -replace ",.*"
@{
     'corp' = ($corpcsv)
     'EUR'  = ($EURcsv)
     'APAC'  = ($APACcsv)
     'NA'  = ($NAcsv)
     'ROOT AD'  = ($ROOTADcsv)
     'Global'  = ($Globalcsv)
     'ICAPRoot'  = ($ICAPROOTcsv)
     'ICAP'  = ($ICAPcsv)
     'US'  = ($UScsv)


   }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")


}
}
New-UDColumn -size 4 {

New-UDChart -Type HorizontalBar -Labels 'Labels'  -Endpoint {  
     #Failed Tests#
     #Corp
     $corpcountfailed = $Cache:corpDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count
     $corpprocessfailed1 = $corpcountfailed -replace  '.*=' 
     $corpfailedfinal = $corpprocessfailed1 -replace '$*}'

     #EUR
     $eurcountfailed = $Cache:EURDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
     $eurprocessfailed1 = $eurcountfailed -replace  '.*=' 
     $eurfailedfinal = $eurprocessfailed1 -replace '$*}'

     #ICAP Root Domain
     $ICAPROOTcountfailed = $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count
     $ICAPROOTprocessfailed1 = $ICAPROOTcountfailed -replace  '.*=' 
     $ICAPROOTfailedfinal = $ICAPROOTprocessfailed1 -replace '$*}'

     #ROOTAD
     $ROOTADcountfailed = $Cache:ROOTADDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count
     $ROOTADprocessfailed1 = $ROOTADcountfailed -replace  '.*=' 
     $ROOTADfailedfinal = $ROOTADprocessfailed1 -replace '$*}'

     #NA
     $NAcountfailed = $Cache:NADcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
     $NAprocessfailed1 = $NAcountfailed -replace  '.*=' 
     $NAfailedfinal = $NAprocessfailed1 -replace '$*}'

     #APAC
      $APACcountfailed = $Cache:APACDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count  
      $APACprocessfailed1 = $NAcountfailed -replace  '.*=' 
      $APACfailedfinal = $NAprocessfailed1 -replace '$*}' 

      #GLOBAL
      $GLOBALcountfailed = $Cache:GLOBALADDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
      $GLOBALprocessfailed1 = $GLOBALcountfailed -replace  '.*=' 
      $GLOBALfailedfinal = $GLOBALprocessfailed1 -replace '$*}'

      #US
      $UScountfailed = $Cache:USDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
      $USprocessfailed1 = $UScountfailed -replace  '.*=' 
      $USfailedfinal = $USprocessfailed1 -replace '$*}'


     
     ####################################################
     #Passed Tests#
     #corp
     $corpcountPassed = $Cache:corpDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $corpprocesspassed1 = $corpcountPassed -replace  '.*=' 
     $corpPassedfinal = $corpprocesspassed1 -replace '$*}'

     #EUR
     $eurcountPassed = $Cache:EURDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $eurprocesspassed1 = $eurcountPassed -replace  '.*=' 
     $eurPassedfinal = $eurprocesspassed1 -replace '$*}'

     #ICAP Root Domain
     $ICAPROOTcountPassed = $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $ICAPROOTprocesspassed1 = $ICAPROOTcountPassed -replace  '.*=' 
     $ICAPROOTPassedfinal = $ICAPROOTprocesspassed1 -replace '$*}'

     #ROOTAD
     $ROOTADcountPassed = $Cache:ROOTADDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $ROOTADprocesspassed1 = $ROOTADcountPassed -replace  '.*=' 
     $ROOTADPassedfinal = $ROOTADprocesspassed1 -replace '$*}'

     #NA
     $NAcountPassed = $Cache:NADcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $NAprocesspassed1 = $NAcountPassed -replace  '.*=' 
     $NAPassedfinal = $NAprocesspassed1 -replace '$*}'

     #APAC
     $APACcountPassed = $Cache:APACDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count 
     $APACprocesspassed1 = $APACcountPassed -replace  '.*=' 
     $APACPassedfinal = $APACprocesspassed1 -replace '$*}' 

     #GLOBAL
     $GLOBALcountPassed = $Cache:GLOBALADDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $GLOBALprocesspassed1 = $GLOBALcountPassed -replace  '.*=' 
     $GLOBALPassedfinal = $GLOBALprocesspassed1 -replace '$*}'

     #US
     $UScountPassed = $Cache:USDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $USprocesspassed1 = $UScountPassed -replace  '.*=' 
     $USPassedfinal = $USprocesspassed1 -replace '$*}'

     ############################################################
     #Passed with Remarks#
     #Corp
     $corpcountPassedwithremarks = $Cache:corpDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
     $ICAPROOTpassedremarks = $ICAPROOTcountPassedwithremarks -replace  '.*=' 
     $ICAPROOTpassedremarksfinal =  $ICAPROOTpassedremarks -replace '$*}'

     #EUR
     $eurcountPassedwithremarks = $Cache:EURDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
     $eurpassedremarks = $eurcountPassedwithremarks -replace  '.*=' 
     $eurpassedremarksfinal =  $eurpassedremarks -replace '$*}'

     #ICAP Root Domain
     $ICAPROOTcountPassedwithremarks = $Cache:ICAPROOTDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
     $ICAPROOTpassedremarks = $ICAPROOTcountPassedwithremarks -replace  '.*=' 
     $ICAPROOTpassedremarksfinal =  $ICAPROOTpassedremarks -replace '$*}'

     #ROOTAD
     $ROOTADcountPassedwithremarks = $Cache:ROOTADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
     $ROOTADpassedremarks = $ROOTADcountPassedwithremarks -replace  '.*=' 
     $ROOTADpassedremarksfinal =  $ROOTADpassedremarks -replace '$*}'

     #NA
     $NAcountPassedwithremarks = $Cache:NADcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
     $NApassedremarks = $NAcountPassedwithremarks -replace  '.*=' 
     $NApassedremarksfinal =  $NApassedremarks -replace '$*}'

     #APAC
     $APACcountPassedwithremarks = $Cache:APACDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count  
     $APACpassedremarks = $APACcountPassedwithremarks -replace  '.*=' 
     $APACpassedremarksfinal =  $APACpassedremarks -replace '$*}' 

     #GLOBAL
     $GLOBALcountPassedwithremarks = $Cache:GLOBALADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 
     $GLOBALpassedremarks = $GLOBALcountPassedwithremarks -replace  '.*=' 
     $GLOBALpassedremarksfinal =  $GLOBALpassedremarks -replace '$*}' 

     #US
     $UScountPassedwithremarks = $Cache:USDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count  
     $USpassedremarks = $UScountPassedwithremarks -replace  '.*=' 
     $USpassedremarksfinal =  $USpassedremarks -replace '$*}' 

        @(
            [PSCustomObject]@{ 
            'ID' = 'All Domain Test Results' 
            'Passed' = [int]$corpPassedfinal + [int]$eurPassedfinal + [int]$ICAPROOTPassedfinal + [int]$ROOTADPassedfinal + [int]$NAPassedfinal + [int]$APACPassedfinal + [int]$GLOBALPassedfinal + [int]$USPassedfinal
            'Failed' = [int]$corpfailedfinal + [int]$eurfailedfinal + [int]$ICAPROOTfailedfinal + [int]$ROOTADfailedfinal + [int]$NAfailedfinal + [int]$APACfailedfinal + [int]$GLOBALfailedfinal + [int]$USfailedfinal
            'Passed with Remarks' = [int]$corppassedremarksfinal + [int]$eurpassedremarksfinal + [int]$ICAPROOTpassedremarksfinal + [int]$ROOTADpassedremarksfinal + [int]$NApassedremarksfinal + [int]$APACpassedremarksfinal + [int]$GLOBALpassedremarksfinal + [int]$USpassedremarksfinal
                      }
         ) | Out-UDChartData -LabelProperty ID -Dataset @(
       New-UdChartDataset -Label "Passed" -DataProperty "Passed" -BackgroundColor "green" -HoverBackgroundColor "green" 
       New-UdChartDataset -Label "Failed" -DataProperty "Failed" -BackgroundColor "red" -HoverBackgroundColor "red"
       New-UdChartDataset -Label "Passed with Remarks" -DataProperty "Passed with Remarks" -BackgroundColor "yellow" -HoverBackgroundColor "yellow"
       
    )
}

}
New-UDColumn -Size 5 {
 New-UdGrid -Title 'corp DC Connection failure for the past 24 hours' -Headers @("Investigate","Ping Status","Name","Ping Date","Uptime") -Properties @("Investigate","Ping Status","Name","Ping Date","Uptime")  -AutoRefresh -PageSize 10 -Endpoint {
       $Cache:CorpDCPing24  | Out-UDGridData
       }
 New-UDButton -text "AOTM"  -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UdGrid -Title "As Of The Moment" -Headers @("Investigate","Ping Status","Name","Ping Date","Uptime") -Properties @("Investigate","Ping Status","Name","Ping Date","Uptime") -PageSize 100  -Endpoint {

                                         $Domain = "corp.ad.tullib.com"



# Code
$DCs = Get-ADDomainController -filter * -server "$Domain"   
$AllDCs = $DCs  | foreach {$_.hostname} #| Where-Object {$_.hostname -like "LDNPINFDCG0*"} 

$DCTest =  Foreach($computer in $DCs) {

    if (Test-Connection -ComputerName $computer -Quiet)
    {

    $LastBoot = (Get-WmiObject -Class Win32_OperatingSystem -computername $computer).LastBootUpTime
    $sysuptime = (Get-Date) – [System.Management.ManagementDateTimeconverter]::ToDateTime($LastBoot)

    $days = $sysuptime.Days
    $DaystoHours = ($sysuptime.Days)*24
    $hours = $sysuptime.hours
    $TotalHours = $DaystoHours + $hours
    $TodaysDate = Get-Date

        if($TotalHours -gt '24')
        {
            New-Object -TypeName PSCustomObject -Property @{
                                                            Name = $computer
                                                     'Ping Date' = $TodaysDate
                                                   'Ping Status' = 'Ok'
                                                   'Investigate' = 'No'
                                                        'Uptime' = "$days Days and $hours Hours"
                                                        

}
        }
        else
        {
            New-Object -TypeName PSCustomObject -Property @{
                                                            Name = $computer
                                                     'Ping Date' = $TodaysDate
                                                   'Ping Status' = 'Ok'
                                                   'Investigate' = 'Yes'
                                                        'Uptime' = "$days Days and $hours Hours"
                                                        

}
        }
    }
    else
        {
           New-Object -TypeName PSCustomObject -Property @{
                                                            Name = $computer
                                                     'Ping Date' = $TodaysDate
                                                   'Ping Status' = 'Failed'
                                                   'Investigate' = 'Yes'
                                                        'Uptime' = 'Unable to Reach the Domain Controller'
                                                        

}
        }
}





                                         $DCTest   | Out-UDGridData

                                         }
                                        }
                                         
                                       }
                                      }
 New-UDButton -text "24 Full"  -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UdGrid -Title "24 Full" -Headers @("Investigate","Ping Status","Name","Ping Date","Uptime") -Properties @("Investigate","Ping Status","Name","Ping Date","Uptime") -PageSize 100  -Endpoint {

                                         $Cache:CorpDCPing24Full  | Out-UDGridData

                                         }
                                        }
                                         
                                       }
                                      }
 New-UDButton -text "1 Week"  -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UdGrid -Title "1 Week Full" -Headers @("Investigate","Ping Status","Name","Ping Date","Uptime") -Properties @("Investigate","Ping Status","Name","Ping Date","Uptime") -PageSize 100 -Endpoint {

                                         $Cache:CorpDCPing7  | Out-UDGridData

                                         }
                                        }
                                         
                                       }
                                      }
 New-UDButton -text "1 Month"  -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UdGrid -Title "1 Month" -Headers @("Investigate","Ping Status","Name","Ping Date","Uptime") -Properties @("Investigate","Ping Status","Name","Ping Date","Uptime") -PageSize 100 -Endpoint {

                                         $Cache:CorpDCPing30  | Out-UDGridData

                                         }
                                        }
                                         
                                       }
                                      }
 
}
}
}
New-UDTabContainer -Tabs{
New-UDTab  -Text 'DC Diag Overview' -Content {

New-UDColumn -Size 3 {

New-UDTable -Title 'Corp Domain'  -Headers @(" ", " ") -Endpoint {

$corpcountfailed = $Cache:corpDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$corpcountPassed = $Cache:corpDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$corpcountPassedwithremarks = $Cache:corpDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
$corpReplicationCountFailed = $Cache:corpDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count

$corpprocessfailed1 = $corpcountfailed -replace  '.*=' 
$corpfailedfinal = $corpprocessfailed1 -replace '$*}'

$corpprocesspassed1 = $corpcountPassed -replace  '.*=' 
$corpPassedfinal = $corpprocesspassed1 -replace '$*}'

$corppassedremarks = $corpcountPassedwithremarks -replace  '.*=' 
$corppassedremarksfinal =  $corppassedremarks -replace '$*}'

$corpfailedReplication = $corpReplicationCountFailed -replace  '.*='
$corpfailedReplicationFinal = $corpfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($corpPassedfinal)
                                                       'No. Test Failed' = ($corpfailedfinal)
                                                       'No. Test Passed with Remarks' = ($corppassedremarksfinal)
                                                       'No. Replication Test Failed' = ($corpfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Corp test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:corpDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Corp test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:corpDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Corp Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:corpDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed ObjectsReplicated" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Corp Failed ObjectsReplicated Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:corpDcDiag | Where-Object {($_.TestName -eq 'ObjectsReplicated') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed KnowsOfRoleHolders" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Corp Failed KnowsOfRoleHolders Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:corpDcDiag | Where-Object {($_.TestName -eq 'KnowsOfRoleHolders') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }


New-UDTable -Title 'ICAP Root Domain'  -Headers @(" ", " ") -Endpoint {

$ICAPROOTcountfailed = $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$ICAPROOTcountPassed = $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$ICAPROOTcountPassedwithremarks = $Cache:ICAPROOTDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
$ICAPROOTReplicationCountFailed = $Cache:ICAPROOTDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count

$ICAPROOTprocessfailed1 = $ICAPROOTcountfailed -replace  '.*=' 
$ICAPROOTfailedfinal = $ICAPROOTprocessfailed1 -replace '$*}'

$ICAPROOTprocesspassed1 = $ICAPROOTcountPassed -replace  '.*=' 
$ICAPROOTPassedfinal = $ICAPROOTprocesspassed1 -replace '$*}'

$ICAPROOTpassedremarks = $ICAPROOTcountPassedwithremarks -replace  '.*=' 
$ICAPROOTpassedremarksfinal =  $ICAPROOTpassedremarks -replace '$*}'

$ICAPROOTfailedReplication = $ICAPROOTReplicationCountFailed -replace  '.*='
$ICAPROOTfailedReplicationFinal = $ICAPROOTfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($ICAPROOTPassedfinal)
                                                       'No. Test Failed' = ($ICAPROOTfailedfinal)
                                                       'No. Test Passed with Remarks' = ($ICAPROOTpassedremarksfinal)
                                                       'No. Replication Test Failed' = ($ICAPROOTfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ICAP Root test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ICAP Root Passed test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ICAPROOTDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ICAP Root Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ICAPROOTDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed ObjectsReplicated" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ICAP Root Failed ObjectsReplicated Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ICAPROOTDcDiag| Where-Object {($_.TestName -eq 'ObjectsReplicated') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed KnowsOfRoleHolders" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ICAP Root Failed KnowsOfRoleHolders Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ICAPROOTDcDiag | Where-Object {($_.TestName -eq 'KnowsOfRoleHolders') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

                     }
New-UDColumn -Size 3 {

New-UDTable -Title 'Eur Domain'  -Headers @(" ", " ") -Endpoint {

$eurcountfailed = $Cache:EURDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$eurcountPassed = $Cache:EURDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$eurcountPassedwithremarks = $Cache:EURDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 
$eurReplicationCountFailed = $Cache:EURDcDiag| Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count

$eurprocessfailed1 = $eurcountfailed -replace  '.*=' 
$eurfailedfinal = $eurprocessfailed1 -replace '$*}'

$eurprocesspassed1 = $eurcountPassed -replace  '.*=' 
$eurPassedfinal = $eurprocesspassed1 -replace '$*}'

$eurpassedremarks = $eurcountPassedwithremarks -replace  '.*=' 
$eurpassedremarksfinal =  $eurpassedremarks -replace '$*}'

$eurfailedReplication = $eurReplicationCountFailed -replace  '.*='
$eurfailedReplicationFinal = $eurfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($eurPassedfinal)
                                                       'No. Test Failed' = ($eurfailedfinal)
                                                       'No. Test Passed with Remarks' = ($eurpassedremarksfinal)
                                                       'No. Replication Test Failed' = ($eurfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "EUR test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:EURDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Eur test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:EURDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "EUR Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:EURDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed ObjectsReplicated" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "EUR Failed ObjectsReplicated Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:EURDcDiag| Where-Object {($_.TestName -eq 'ObjectsReplicated') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed KnowsOfRoleHolders" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "EUR Failed KnowsOfRoleHolders Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:EURDcDiag | Where-Object {($_.TestName -eq 'KnowsOfRoleHolders') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

New-UDTable -Title 'Root AD Domain'  -Headers @(" ", " ") -Endpoint {

$ROOTADcountfailed = $Cache:ROOTADDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$ROOTADcountPassed = $Cache:ROOTADDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$ROOTADcountPassedwithremarks = $Cache:ROOTADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 
$ROOTADReplicationCountFailed = $Cache:ROOTADDcDiag| Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count

$ROOTADprocessfailed1 = $ROOTADcountfailed -replace  '.*=' 
$ROOTADfailedfinal = $ROOTADprocessfailed1 -replace '$*}'

$ROOTADprocesspassed1 = $ROOTADcountPassed -replace  '.*=' 
$ROOTADPassedfinal = $ROOTADprocesspassed1 -replace '$*}'

$ROOTADpassedremarks = $ROOTADcountPassedwithremarks -replace  '.*=' 
$ROOTADpassedremarksfinal =  $ROOTADpassedremarks -replace '$*}'

$ROOTADfailedReplication = $ROOTADReplicationCountFailed -replace  '.*='
$ROOTADfailedReplicationFinal = $ROOTADfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($ROOTADPassedfinal)
                                                       'No. Test Failed' = ($ROOTADfailedfinal)
                                                       'No. Test Passed with Remarks' = ($ROOTADpassedremarksfinal)
                                                       'No. Replication Test Failed' = ($ROOTADfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ROOTAD test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ROOTADDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ROOTAD test Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ROOTADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Root AD Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ROOTADDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed ObjectsReplicated" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Root AD Failed ObjectsReplicated Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ROOTADDcDiag| Where-Object {($_.TestName -eq 'ObjectsReplicated') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed KnowsOfRoleHolders" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Root AD Failed KnowsOfRoleHolders Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ROOTADDcDiag | Where-Object {($_.TestName -eq 'KnowsOfRoleHolders') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

                     }
New-UDColumn -Size 3 {

New-UDTable -Title 'NA Domain'  -Headers @(" ", " ") -Endpoint {

$NAcountfailed = $Cache:NADcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$NAcountPassed = $Cache:NADcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$NAcountPassedwithremarks = $Cache:NADcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
$NAReplicationCountFailed = $Cache:NADcDiag| Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count

$NAprocessfailed1 = $NAcountfailed -replace  '.*=' 
$NAfailedfinal = $NAprocessfailed1 -replace '$*}'

$NAprocesspassed1 = $NAcountPassed -replace  '.*=' 
$NAPassedfinal = $NAprocesspassed1 -replace '$*}'

$NApassedremarks = $NAcountPassedwithremarks -replace  '.*=' 
$NApassedremarksfinal =  $NApassedremarks -replace '$*}'

$NAfailedReplication = $NAReplicationCountFailed -replace  '.*='
$NAfailedReplicationFinal = $NAfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($NAPassedfinal)
                                                       'No. Test Failed' = ($NAfailedfinal)
                                                       'No. Test Passed with Remarks' = ($NApassedremarksfinal)
                                                       'No. Replication Test Failed' = ($NAfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "NA test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:NADcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "NA Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:NADcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "NA Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:NADcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed ObjectsReplicated" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "NA Failed ObjectsReplicated Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:NADcDiag| Where-Object {($_.TestName -eq 'ObjectsReplicated') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed KnowsOfRoleHolders" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "NA Failed KnowsOfRoleHolders Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:NADcDiag | Where-Object {($_.TestName -eq 'KnowsOfRoleHolders') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

New-UDTable -Title 'APAC Domain'  -Headers @(" ", " ") -Endpoint {

$APACcountfailed = $Cache:APACDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$APACcountPassed = $Cache:APACDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$APACcountPassedwithremarks = $Cache:APACDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
$APACReplicationCountFailed = $Cache:APACDcDiag| Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count 

$APACprocessfailed1 = $APACcountfailed -replace  '.*=' 
$APACfailedfinal = $APACprocessfailed1 -replace '$*}'

$APACprocesspassed1 = $APACcountPassed -replace  '.*=' 
$APACPassedfinal = $APACprocesspassed1 -replace '$*}'

$APACpassedremarks = $APACcountPassedwithremarks -replace  '.*=' 
$APACpassedremarksfinal =  $APACpassedremarks -replace '$*}'

$APACfailedReplication = $APACReplicationCountFailed -replace  '.*='
$APACfailedReplicationFinal = $APACfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($APACPassedfinal)
                                                       'No. Test Failed' = ($APACfailedfinal)
                                                       'No. Test Passed with Remarks' = ($APACpassedremarksfinal)
                                                       'No. Replication Test Failed' = ($APACfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "APAC test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:APACDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "APAC Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:APACDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "APAC Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:APACDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed ObjectsReplicated" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "APAC Failed ObjectsReplicated Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:APACDcDiag| Where-Object {($_.TestName -eq 'ObjectsReplicated') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed KnowsOfRoleHolders" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "APAC Failed KnowsOfRoleHolders Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:APACDcDiag | Where-Object {($_.TestName -eq 'KnowsOfRoleHolders') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

                     }
New-UDColumn -Size 3 {

New-UDTable -Title 'GLOBAL Domain'  -Headers @(" ", " ") -Endpoint {

$GLOBALcountfailed = $Cache:GLOBALADDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$GLOBALcountPassed = $Cache:GLOBALADDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$GLOBALcountPassedwithremarks = $Cache:GLOBALADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 
$GLOBALReplicationCountFailed = $Cache:GLOBALADDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count 

$GLOBALprocessfailed1 = $GLOBALcountfailed -replace  '.*=' 
$GLOBALfailedfinal = $GLOBALprocessfailed1 -replace '$*}'

$GLOBALprocesspassed1 = $GLOBALcountPassed -replace  '.*=' 
$GLOBALPassedfinal = $GLOBALprocesspassed1 -replace '$*}'

$GLOBALpassedremarks = $GLOBALcountPassedwithremarks -replace  '.*=' 
$GLOBALpassedremarksfinal =  $GLOBALpassedremarks -replace '$*}'

$GLOBALfailedReplication = $GLOBALReplicationCountFailed -replace  '.*='
$GLOBALfailedReplicationFinal = $GLOBALfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($GLOBALPassedfinal)
                                                       'No. Test Failed' = ($GLOBALfailedfinal)
                                                       'No. Test Passed with Remarks' = ($GLOBALpassedremarksfinal)
                                                       'No. Replication Test Failed' = ($GLOBALfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "GLOBAL test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:GLOBALADDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "GLOBAL Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:GLOBALADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Global Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:GLOBALADDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed ObjectsReplicated" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Global Failed ObjectsReplicated Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:GLOBALADDcDiag| Where-Object {($_.TestName -eq 'ObjectsReplicated') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed KnowsOfRoleHolders" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "APAC Failed KnowsOfRoleHolders Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:GLOBALADDcDiag | Where-Object {($_.TestName -eq 'KnowsOfRoleHolders') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

New-UDTable -Title 'US Domain'  -Headers @(" ", " ") -Endpoint {

$UScountfailed = $Cache:USDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$UScountPassed = $Cache:USDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$UScountPassedwithremarks = $Cache:USDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 
$USReplicationCountFailed = $Cache:USDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count 

$USprocessfailed1 = $UScountfailed -replace  '.*=' 
$USfailedfinal = $USprocessfailed1 -replace '$*}'

$USprocesspassed1 = $UScountPassed -replace  '.*=' 
$USPassedfinal = $USprocesspassed1 -replace '$*}'

$USpassedremarks = $UScountPassedwithremarks -replace  '.*=' 
$USpassedremarksfinal =  $USpassedremarks -replace '$*}'

$USfailedReplication = $USReplicationCountFailed -replace  '.*='
$USfailedReplicationFinal = $USfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($USPassedfinal)
                                                       'No. Test Failed' = ($USfailedfinal)
                                                       'No. Test Passed with Remarks' = ($USpassedremarksfinal)
                                                       'No. Replication Test Failed' = ($USfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "US test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:USDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "US Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:USDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "US Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:USDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed ObjectsReplicated" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "US Failed ObjectsReplicated Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:USDcDiag| Where-Object {($_.TestName -eq 'ObjectsReplicated') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed KnowsOfRoleHolders" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "US Failed KnowsOfRoleHolders Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:USDcDiag | Where-Object {($_.TestName -eq 'KnowsOfRoleHolders') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

                     }

}
New-UDTab  -Text CORP              -Content {

 New-UdGrid -Title ([string]$Cache:corpDCtitle) -Headers @("ServerName","TestName","Status","Information") -Properties @("ServerName","TestName","Status","Information")  -AutoRefresh -PageSize 100 -Endpoint {
       $Cache:corpDcDiag  | Out-UDGridData
  }
  }
New-UDTab  -Text EUR               -Content {
  
  $EurDCtitle = $Cache:EURpath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $EurDCtitle -Headers @("ServerName","TestName","Status","Information") -Properties @("ServerName","TestName","Status","Information") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:EURDcDiag | Out-UDGridData
  }

  }
New-UDTab  -Text NA                -Content {
  
  $NaDCtitle = $Cache:NApath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $NaDCtitle -Headers @("ServerName","TestName","Status","Information") -Properties @("ServerName","TestName","Status","Information") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:NADcDiag | Out-UDGridData
  }

  }
New-UDTab  -Text GLOBAL            -Content {
  
  $GlobalDCtitle = $Cache:GLOBALADpath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $GlobalDCtitle -Headers @("ServerName","TestName","Status","Information") -Properties @("ServerName","TestName","Status","Information") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:GLOBALADDcDiag | Out-UDGridData
  }

  }
New-UDTab  -Text ICAPRoot          -Content {
  
  $ICAPRootDCTitle = $Cache:ICAPROOTpath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $ICAPRootDCTitle -Headers @("ServerName","TestName","Status","Information") -Properties @("ServerName","TestName","Status","Information") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:ICAPROOTDcDiag | Out-UDGridData
  }

  }
New-UDTab  -Text RootAD            -Content {
  
  $RootADDCTitle = $Cache:ROOTADpath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $RootADDCTitle -Headers @("ServerName","TestName","Status","Information") -Properties @("ServerName","TestName","Status","Information") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:ROOTADDcDiag | Out-UDGridData
  }

  }
New-UDTab  -Text APAC              -Content {
  
  $ApacADDCTitle = $Cache:APACpath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $ApacADDCTitle -Headers @("ServerName","TestName","Status","Information") -Properties @("ServerName","TestName","Status","Information") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:APACDcDiag | Out-UDGridData
  }

  }
New-UDTab  -Text US                -Content {
  
  $USADDCTitle = $Cache:USpath -replace '.*\\' -replace ",.*"
 
 New-UdGrid -Title $USADDCTitle -Headers @("ServerName","TestName","Status","Information") -Properties @("ServerName","TestName","Status","Information") -AutoRefresh -PageSize 100 -Endpoint {
        $Cache:USDcDiag | Out-UDGridData
  }

  }
 }

 }
}     


$ei = New-UDEndpointInitialization -Module @("C:\Program Files\WindowsPowerShell\Modules\VMware.VimAutomation.Core\10.1.0.8344055\VMware.VimAutomation.Core.psm1")
$Dashboard = New-UDDashboard  -Title 'Server Validation Tool' -NavBarLogo (New-UDImage -Path "D:\dashboard\160px-TP_ICAP_logo.svg.png" -Height 70 -Width 80) -Page $pages -EndpointInitialization $ei -Footer $footer 
Start-UDDashboard -AutoReload -Endpoint @($Schedule1,$DCdiagEndpoint) -Dashboard $dashboard  -Wait 