
$servers = Get-Content -Path D:\Temp\sweep\qualys.txt

$username = 'us\us da 2'
$password = 'FDt)H%6mHpHG)9GNT'

$pass =  ConvertTo-SecureString -String $password -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass

$process = foreach($ServerName in $servers){do{

$Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ServerName -Credential $creds -ErrorAction SilentlyContinue  | ? {$_.IPEnabled} 

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
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name Servername -Value $ServerName                        
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name Gateway -Value $DefaultGateway
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value $DNSServers            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress            
                                                                   $OutputObj 

                                                                   }while($false)} 

                                                                  $process |Select-Object servername,IPAddress,Subnetmask,gateway,@{N="DNSServers";E={[string]$_.DNSServers}},macaddress | Export-Csv D:\Temp\sweep\USDnsResult.csv