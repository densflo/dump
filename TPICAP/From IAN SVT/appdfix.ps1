

##stop APPD Services##
Stop-Service -Name *appdynamics* -force

Wait-Process -Name *appdynamics*

##move 7za.exe##

$currentdir = Get-Location

Move-Item -Path "$currentdir\7za.exe" -Destination "C:\Program Files\AppDynamics\MachineAgent\lib"

###create a folder###

New-Item -Path "C:\ProgramData\AppDynamics\backup\MachineAgent" -name "log4j" -ItemType "directory"

### getting the log4j files and Moving Log4j file to backup folder####


Get-ChildItem -Path "C:\Program Files\AppDynamics\MachineAgent\lib" -Filter log4j-core* | select -ExpandProperty name | Copy-Item -Destination "C:\ProgramData\AppDynamics\backup\MachineAgent\log4j"

#running the 7zip command#

Set-Location 'C:\Program Files\AppDynamics\MachineAgent\lib'
cmd.exe /c  '7za.exe d log4j-core *log4j-core.jar org/apache/logging/log4j/core/lookup/JndiLookup.class'

##Start APPD Services###

Start-Service -Name *appdynamics* 






