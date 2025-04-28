       $username = "corp\corp da 2"
       $pass =  ConvertTo-SecureString -String 'ZhA4tO(Cd5^^w1IY30^g' -AsPlainText -Force
       $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass
                                                              
                                         

                                       


                                      $Servers  = Get-Content -Path "C:\temp\servers.txt"

                                    $AppdAgent =  foreach ($ServerName in $Servers){
                                      if (Get-WMIObject -Query "select * from win32_service where name='Appdynamics Machine Agent'" -computer $ServerName -Credential $creds -ErrorAction SilentlyContinue){
                                                        Get-WMIObject -Query "select * from win32_service where name='Appdynamics Machine Agent'" -ComputerName $ServerName -Credential $creds |select @{N="ServerName";E={[string]$ServerName}},name,startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Servername= [string]$ServerName
                                                                                                       Name      = "Appdynamics Machine Agent"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} } 
                                                                                                       }

                                                                                                       

                                                                       $AppdAgent | ft