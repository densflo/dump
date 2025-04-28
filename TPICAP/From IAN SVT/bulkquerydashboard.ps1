
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
        }
    }
    $Cache:ViServerList = $global:DefaultVIServer
}




  

  

  
$footer =  New-UDFooter -Copyright "Created and Developed by Ian Navarrete 2020"
$pages = @()

$pages += New-UDPage -name "Bulk Query"  -Content {

New-UDLayout -Columns 4 -Content {
   
   New-UDCard -Title "Please access the Shared folder \\LDNPINFADM05\bulk
                      to input data" -TitleAlignment left  -Content {
                               
                                      

                                    }
   New-UDColumn -LargeSize 12 {
    
    New-UDInput  -Title "APPD Service check" -Content {
    
                    New-UDInputField -Type textbox -Name UserName -Placeholder 'User Name with domain'
                    New-UDInputField -Type password -Name Password -Placeholder 'Password'
    
       }-SubmitText "Connect" -Endpoint{ 
       
       param($username,$password)

       $pass =  ConvertTo-SecureString -String $password -AsPlainText -Force
       $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass
                                                              
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {
                                         New-UDTable -Title "AppD Service Check"  -Headers @("Servername","Name","StartMode","State","Status") -Endpoint {


                                      $Servers  = Get-Content -Path "D:\bulk\AppDservice.txt"

                                    $AppdAgent =  foreach ($ServerName in $Servers){
                                      if (Get-WMIObject -Query "select * from win32_service where name='Appdynamics Machine Agent'" -computer $ServerName -Credential $creds){
                                                        Get-WMIObject -Query "select * from win32_service where name='Appdynamics Machine Agent'" -ComputerName $ServerName -Credential $creds |select @{N="ServerName";E={[string]$ServerName}},name,startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Servername= [string]$ServerName
                                                                                                       Name      = "Appdynamics Machine Agent"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} } 
                                                                                                       }


                                                                                                       

                                                                       $AppdAgent | Out-UDTableData -Property @("Servername","Name","StartMode","State","Status") 
                                                                   }  

                                                                        
                                            
                                            
                                            

                                         }
                                         }
                                         } 

   
    }
   New-UDColumn -LargeSize 12 {
    
    New-UDInput  -Title "Bulk Ping" -Content {
    
                    
    
       }-SubmitText "Connect" -Endpoint{ 
       
       

       
                                                              
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {
                                         New-UDTable -Title "$servercheck Ping" -AutoRefresh  -Headers @("Name","Ping Status","FQDN") -Endpoint {

                                    $servers = Get-Content -Path "D:\bulk\bulkping.txt"
                                    $ping    = foreach ($server in $servers){
                                            if(Test-Connection -ComputerName $server -Quiet -Count 1 -ErrorAction SilentlyContinue) {
                                            New-Object -TypeName PSCustomObject -Property @{
                                             Name = $server
                                            'Ping Status' = 'Ok'
                                            'FQDN' = [net.dns]::GetHostEntry($server).Hostname 
                                                }
                                                    } elseif(Test-Connection -ComputerName $server -Quiet -Count 1 -ErrorAction SilentlyContinue) {
                                                                New-Object -TypeName PSCustomObject -Property @{
                                                                Name = $server
                                                               'Ping Status' = 'Failed'
                                                               'FQDN' = [net.dns]::GetHostEntry($server).Hostname
                                                                } 
                                                                 } else {
                                                                New-Object -TypeName PSCustomObject -Property @{
                                                                Name = $server
                                                               'Ping Status' = 'Failed'
                                                               'FQDN' = 'no DNS data'
                                                                  
                                                                   } 
                                                                  }
                                                                 }

                                    $ping  | Out-UDTableData -Property @("Name","Ping Status","FQDN")
                                                                   
                                                                   
                                                                   
                                                                   }
                                                                        
                                            
                                            
                                            

                                         }
                                         }
                                         } 

   
    }
   New-UDColumn -LargeSize 12 {
    
    New-UDInput  -Title "Bulk Uptime" -Content {
    
                    New-UDInputField -Type textbox -Name UserName -Placeholder 'User Name with domain'
                    New-UDInputField -Type password -Name Password -Placeholder 'Password'
    
       }-SubmitText "Connect" -Endpoint{ 
       
       param($username,$password)

       $pass =  ConvertTo-SecureString -String $password -AsPlainText -Force
       $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass
                                                              
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {
                                         New-UDTable -Title  "UpTime" -AutoRefresh -Headers @('ServerName','Last Boot','Uptime') -Endpoint {

                                                           $servers = Get-Content -Path "D:\bulk\uptime.txt"
                                   $uptime   = foreach ($servername in $servers){
                                                           $userSystem = Get-WmiObject win32_operatingsystem -ComputerName $ServerName -Credential $creds -ErrorAction SilentlyContinue 
                                                           $sysuptime= (Get-Date) - $userSystem.ConvertToDateTime($userSystem.LastBootUpTime)
                                                           $lastboot = ($userSystem.ConvertToDateTime($userSystem.LastBootUpTime) )
                                                           $uptime = ([string]$sysuptime.Days + " Days " + $sysuptime.Hours + " Hours " + $sysuptime.Minutes + " Minutes" ) 
                                                           $propHash = [ordered]@{

                                                                Servername   = $ServerName  
                                                                BootTime     = $lastboot 
                                                                Uptime       = $Uptime
                                                           
                                                               }
                                                            $objComputerUptime = New-Object PSOBject -Property $propHash 
                                                            $objComputerUptime  
                                                                 }

                                                                 $uptime | Out-UDTableData -Property @("ServerName","BootTime","Uptime")
                         
                                                               }  

                                                                        
                                            
                                            
                                            

                                         }
                                         }
                                         } 

   
    }
   
  }
}

$ei = New-UDEndpointInitialization -Module @("C:\Program Files\WindowsPowerShell\Modules\VMware.VimAutomation.Core\10.1.0.8344055\VMware.VimAutomation.Core.psm1")
$Dashboard = New-UDDashboard  -Title 'Server Bulk Query Tool v1' -Theme $theme -FontColor white -NavBarFontColor white -Page $pages -EndpointInitialization $ei -Footer $footer 
Start-UDDashboard -Port 10003 -Dashboard $Dashboard -Endpoint @($Schedule)