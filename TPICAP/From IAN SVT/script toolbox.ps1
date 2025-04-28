


#Author: Ian Navarrete#


if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }


Clear-Host




Function IS-tools{

param ( [string]$title = 'Main Menu')
Clear-Host
                                        Write-Host "

                                        
                                                   My Script Toolbox


                                               Developed By Ian Navarrete
                                                    

                                                   "
                       Write-Host "1:  Get Server Nic Details"
                       Write-Host "2:  Ping Sweep"
                       Write-Host "3:  Build Check Script Deployment"
                       Write-Host "4:  Check AD Locked Out"
                       Write-Host "5:  Check Servers Uptime"
                       Write-Host "6:  Check Computer objects on AD"
                       Write-host "7:  Check server local admin"
                       Write-host "8:  Check Server Drives Space"
                       Write-host "9:  Bulk File Share"
                       Write-Host "10: Check Server Uptime"
                       Write-host "11: SVT"
                       Write-Host " Q: Quit"

}
                       Function Get-NicDetails { 
[cmdletbinding()]            
param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)                        
            
begin {}            
process {            
 foreach ($Computer in $ComputerName) {            
  if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {            
   try {            
    $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $Computer -EA Stop | ? {$_.IPEnabled}            
   } catch {            
        Write-Warning "Error occurred while querying $computer."            
        Continue            
   }            
   foreach ($Network in $Networks) {            
    $IPAddress  = $Network.IpAddress[0]            
    $SubnetMask  = $Network.IPSubnet[0]            
    $DefaultGateway = $Network.DefaultIPGateway            
    $DNSServers  = $Network.DNSServerSearchOrder            
    $IsDHCPEnabled = $false            
    If($network.DHCPEnabled) {            
     $IsDHCPEnabled = $true            
    }            
    $MACAddress  = $Network.MACAddress            
    $OutputObj  = New-Object -Type PSObject            
    $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.ToUpper()            
    $OutputObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress            
    $OutputObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask            
    $OutputObj | Add-Member -MemberType NoteProperty -Name Gateway -Value $DefaultGateway            
    $OutputObj | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled            
    $OutputObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value $DNSServers            
    $OutputObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress            
    $OutputObj            
   }            
  }            
 }            
}            
            
end {}

}
                       Function Get-Uptime { 
    [CmdletBinding()] 
    param ( 
        [Parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)] 
        [Alias("Name")] 
        [string[]]$ComputerName=$env:COMPUTERNAME, 
        $Credential = [System.Management.Automation.PSCredential]::Empty 
        ) 
 
    begin{} 
 
    #Need to verify that the hostname is valid in DNS 
    process { 
        foreach ($Computer in $ComputerName) { 
            try { 
                
                $OS = Get-WmiObject win32_operatingsystem -ComputerName $Computer -ErrorAction Stop -Credential $Credential 
                $BootTime = $OS.ConvertToDateTime($OS.LastBootUpTime) 
                $Uptime = $OS.ConvertToDateTime($OS.LocalDateTime) - $boottime 
                $propHash = [ordered]@{ 
                    ComputerName = $Computer 
                    BootTime     = $BootTime 
                    Uptime       = $Uptime 
                    } 
                $objComputerUptime = New-Object PSOBject -Property $propHash 
                $objComputerUptime 
                }  
            catch [Exception] { 
                Write-Output "$computer $($_.Exception.Message)" 
                #return 
                } 
        } 
    } 
    end{} 
}
                       function get-localadmin {  
param ($strcomputer)  
  
$admins = Get-WmiObject win32_groupuser –computer $strcomputer   
$admins = $admins |? {$_.groupcomponent –like '*"Administrators"'}  
  
$admins |% {  
$_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul  
$matches[1].trim('"') + “\” + $matches[2].trim('"')  
}  
}
                       Function Ping-options{

param ( [string]$title = 'Main Menu')
Clear-Host
                                        Write-Host "

                                        
                                              Ping Options


                                             
                                                    

                                                   "
                       Write-Host "1: Ping Sweep ON Screen"
                       Write-Host "2: Ping Sweep With Outfile"
                       Write-Host "M: Main Menu"

}
                       Function Nic-options{

param ( [string]$title = 'Main Menu')
Clear-Host
                                        Write-Host "

                                        
                                              Nic Options


                                             
                                                    

                                                   "
                       Write-Host "1: Single Server"
                       Write-Host "2: Multiple Servers"
                       Write-Host "M: Main Menu"

}
                       Function BuildCheck-options{

param ( [string]$title = 'Main Menu')
Clear-Host
                                        Write-Host "

                                        
                                              Build Check Options


                                             
                                                    

                                                   "
                       Write-Host "1: Single Server Check"
                       Write-Host "2: Multiple Server Check"
                       Write-Host "M: Main Menu"

}


  

 do{
                       
                        IS-tools
                 
                       $Action=""; while($Action -eq ""){ $Action = Read-Host "Choose an option" }
                       
                       
                       if ($Action -eq '1'){
  
                                         Nic-options

                                                  $Action=""; while($Action -eq ""){ $Action = Read-Host "Choose an option" }

                                                  If ($Action -eq '1'){
                                                  
                                                   $servername = (Read-Host "Server Name")
                                                   $CorpDCusername = (Read-Host "UserName")  
                                                   $CorpDCpass =  ConvertTo-SecureString -String (Read-Host "Password" -AsSecureString) -AsPlainText -Force 
                                                   $CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass          
                                                             
                                                    
if(Test-Connection -ComputerName $servername -Quiet){

$Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $servername -Credential $CorpCreds  -EA Stop | ? {$_.IPEnabled}

[PSCustomObject]@{
                 'Server Name' = $servername
                 IPAddress = $Network.IPAddress
                 SubnetMask = $Network.IPSubnet
                 DefaultGateway = $Network.DefaultIPGateway
                 DHCPEnabled = $Network.DHCPEnabled
                 DnsServer = $Network.DNSServerSearchOrder


                 }

}else{

[PSCustomObject]@{
                 'Server Name' = $servername
                 IPAddress = 'Unable to connect'
                 SubnetMask = 'Unable to connect'
                 DefaultGateway = 'Unable to connect'
                 DHCPEnabled = 'Unable to connect'
                 DnsServer = 'Unable to connect'


                 }    
                                                             
                                                             
                                                             
                                                             }

                              }
                                                  if ($Action -eq '2'){
                                            
$servers = Get-Content -Path (Read-Host "Txt Path")  
$CorpDCusername = (Read-Host "UserName")  
$CorpDCpass =  ConvertTo-SecureString -String (Read-Host "Password" -AsSecureString) -AsPlainText -Force 
$CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass




$IPresult = foreach($servername in $servers){

if(Test-Connection -ComputerName $servername -Quiet){

$Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $servername -Credential $CorpCreds  -EA Stop | ? {$_.IPEnabled}
Write-Host "Checking $servername" -BackgroundColor Green -ForegroundColor Black
[PSCustomObject]@{
                 'Server Name' = $servername
                 IPAddress = $Network.IPAddress
                 SubnetMask = $Network.IPSubnet
                 DefaultGateway = $Network.DefaultIPGateway
                 DHCPEnabled = $Network.DHCPEnabled
                 DnsServer = $Network.DNSServerSearchOrder


                 }

}else{
Write-Host "$servername not Pingable" -BackgroundColor Red -ForegroundColor Black
[PSCustomObject]@{
                 'Server Name' = $servername
                 IPAddress = 'Unable to connect'
                 SubnetMask = 'Unable to connect'
                 DefaultGateway = 'Unable to connect'
                 DHCPEnabled = 'Unable to connect'
                 DnsServer = 'Unable to connect'


                 }


  }

}


$IPresult | FT 
Read-Host 'hit enter'
                                            }
                                                  if ($Action -eq 'M'){IS-tools}
  

  }
                       if ($Action -eq '2'){
                       
                                                  Ping-options

                                                  $Action=""; while($Action -eq ""){ $Action = Read-Host "Choose an option" }

                                                  If ($Action -eq '1'){$ServerName = (Get-Content -Path (read-host 'Txt File Path'))
                                             Write-Host (Get-Date)
                                             Write-Host START PING -BackgroundColor yellow -ForegroundColor DarkRed
                                             ForEach ($_ in $servername){
                                                                            if(Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue) 
                                                                            {
                                                                                write-host "Available host ---> "$_ -BackgroundColor Green -ForegroundColor black 
                                                                                [Array]$available += $_
                                                                                }
                                                                                
                                                                                else
                                                                                {
                                                                                    write-host "Unavailable host ------------> "$_ -BackgroundColor red -ForegroundColor black 
                                                                                    if(!(Test-Connection -ComputerName $_ -count 1 -ea SilentlyContinue))
                                                                                    {
                                                                                    }
                                                                                    }
                                                                                    }}
                                                  if ($Action -eq '2'){
                                            $Servers = (Get-Content -Path (read-host "txt path"))
                                            $outfile = (read-host "out file")

                                            $ping = ForEach ($server in $Servers) {
                                            if(Test-Connection -ComputerName $server -Quiet -Count 1) {
                                            New-Object -TypeName PSCustomObject -Property @{
                                            Name = $server
                                            'Ping Status' = 'Ok'
                                            'FQDN' = [net.dns]::GetHostEntry($server).Hostname
                                                }
                                                    } else {
                                                                New-Object -TypeName PSCustomObject -Property @{
                                                                Name = $Server
                                                               'Ping Status' = 'Failed'
                                                                }
                                                                 }
                                                                    } 

                                                                        $ping | Export-Csv -Path $outfile\PingResults.csv -NoTypeInformation
                                            }
                                                  if ($Action -eq 'M'){IS-tools}
                       }
                       if ($Action -eq '3'){
                       
                                                 Buildcheck-options

                                                  $Action=""; while($Action -eq ""){ $Action = Read-Host "Choose an option" }

                                                  If ($Action -eq '1'){
$servername = (Read-Host 'Server name')
$CorpDCusername = (Read-Host 'UserName')
$CorpDCpass =  ConvertTo-SecureString -String (Read-Host 'Password' -AsSecureString) -AsPlainText -Force
$CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass


if(Test-Connection -ComputerName $servername -Quiet){
Write-Host "sending and running script on $servername" -BackgroundColor Green -ForegroundColor Black
$sess = New-PSSession -ComputerName $servername -Credential $CorpCreds
Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {New-Item "c:\temp" -ItemType directory -ErrorAction SilentlyContinue}
Copy-Item  "\\10.90.80.243\bulk\new\script\toolbox\Build-LocalCheck.ps1" -Destination 'c:\temp' -Recurse -ToSession $sess
Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {powershell.exe  'C:\temp\Build-LocalCheck.ps1'  } -ErrorAction SilentlyContinue
Write-Host "Done running script on $servername Please check your email" -BackgroundColor Green -ForegroundColor Black
}else{Write-Host "Unable to reach $servername" -BackgroundColor Red -ForegroundColor Black}
Read-Host 'hit enter'

                                                                                    
                                                        }
                                                  if ($Action -eq '2'){
$servers = Get-Content (Read-Host 'txt Path')
$CorpDCusername = (Read-Host 'UserName')
$CorpDCpass =  ConvertTo-SecureString -String (Read-Host 'Password' -AsSecureString) -AsPlainText -Force
$CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass

foreach($servername in $servers){
if(Test-Connection -ComputerName $servername -Quiet){
Write-Host "sending and running script on $servername" -BackgroundColor Green -ForegroundColor Black
$sess = New-PSSession -ComputerName $servername -Credential $CorpCreds
Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {New-Item "c:\temp" -ItemType directory -ErrorAction SilentlyContinue}
Copy-Item  "\\10.90.80.243\bulk\new\script\toolbox\Build-LocalCheck.ps1" -Destination 'c:\temp' -Recurse -ToSession $sess
Invoke-Command -Computer $servername -Credential $CorpCreds  -ScriptBlock {powershell.exe  'C:\temp\Build-LocalCheck.ps1'  } -ErrorAction SilentlyContinue
Write-Host "Done running script on $servername Please check your email" -BackgroundColor Green -ForegroundColor Black
remove-p
}else{Write-Host "Unable to reach $servername" -BackgroundColor Red -ForegroundColor Black}


}
Read-Host 'hit enter'
                                            }
                                                  if ($Action -eq 'M'){IS-tools}
                       }                                  
                       if ($Action -eq '4'){do
                                             {
                                                
$ErrorActionPreference = "SilentlyContinue"
Clear-Host
$User = Read-Host -Prompt "Please enter a user name"
#Locate the PDC
$PDC = (Get-ADDomainController -Discover -Service PrimaryDC).Name
#Locate all DCs
$DCs = (Get-ADDomainController -Filter *).Name #| Select-Object name
foreach ($DC in $DCs) {
Write-Host -ForegroundColor Green "Checking events on $dc for User: $user"
if ($DC -eq $PDC) {
    Write-Host -ForegroundColor Green "$DC is the PDC"
    }
    Get-WinEvent -ComputerName $DC -Logname Security -FilterXPath "*[System[EventID=4740 or EventID=4625 or EventID=4770 or EventID=4771 and TimeCreated[timediff(@SystemTime) <= 3600000]] and EventData[Data[@Name='TargetUserName']='$User']]" | Select-Object TimeCreated,@{Name='User Name';Expression={$_.Properties[0].Value}},@{Name='Source Host';Expression={$_.Properties[1].Value}} -ErrorAction SilentlyContinue
}



                                                 }while ($flase)
                                               }
                       if ($Action -eq '5'){do
                                             {
                                               Get-Uptime -ComputerName (read-host 'Server Name')  

                                               Read-Host 'hit enter'
                                               
                                               }while ($false)
                                             }
                       if ($Action -eq '6'){
                                            $outloc = read-host 'Out File location EX: C:\windows\user\ian\desktop'

                                            Get-ADComputer -Filter * -Property * | Select-Object name, dnshostname, operatingsystem, Enabled, CanonicalName, distinguishedname | Export-Csv $outloc\adcompextract.csv -NoTypeInformation -Encoding UTF8   
                                             }
                       if ($Action -eq '7'){
                                                $servers = (Read-Host "Server Name")
                                                           

                                                 get-localadmin -strcomputer $servers | ft 
                                            }
                       if ($Action -eq '8'){
                                            

                                             $servername = Read-host 'type server name'

                                             Get-WmiObject win32_logicaldisk -ComputerName $Servername  -ErrorAction SilentlyContinue | Select-Object deviceID,@{n="FreeSpace";e={ [Math]::truncate($_.FreeSpace / 1GB)}},@{n="size";e={ [Math]::truncate($_.Size / 1GB)}}

                                            }
                       if ($Action -eq '9'){
                                                $ie = New-Object -ComObject internetexplorer.application
                                                    $ie.Navigate("\\10.90.80.243\bulk")
                                                    $ie.visible = $true
                                             
                                             }
                       if ($Action -eq '10'){do
                                             {
                                               $servers =  Read-Host 'file location'
                                               
                                               Write-host "
                                               
                                               Include ** for wildcard search
                                                          
                                                          "
                                                          $service = (Read-Host 'service')
                                                          Get-Service $service -ComputerName $servers | select machinename,name,status,displayname | sort machinename | format-table -autosize
                                                          
                                                          Read-Host 'hit enter'
                                                          }while($false)
                                                          }
                       if ($Action -eq '11'){
                                                $ie = New-Object -ComObject internetexplorer.application
                                                    $ie.Navigate("http://ldn1ws9724/SVT")
                                                    $ie.visible = $true
                                             
                                             }
                       if ($Action -eq 'M'){IS-tools}
                       if ($Action -eq 'Q'){exit}

                       Read-Host -Prompt "please hit enter"
}while ($true)


                      

