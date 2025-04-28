


$results = New-Object System.Collections.ArrayList
$Computers = Get-Content -Path D:\servers.txt
 
Foreach ($Computer in $Computers) 
{
   set-location "\\$computer\c$\Program Files\AppDynamics\MachineAgent\monitors" -ErrorAction SilentlyContinue
    
        $file = Get-ChildItem  | Where-Object {$_.name -notmatch 'analytics-agent|HardwareMonitor|JavaHardwareMonitor|ProcessMonitor|.DS_Store'} 


        
 
        $results += New-Object psObject -Property @{'Computer'=$computer;'FileName'=([string]$file) ;'LastWriteTime'=$file.lastwritetime; 'Size'=($file | Get-ChildItem).count}
   
 
 
 }
    $results
   




                                   