$servicename = 'Appdynamics Machine Agent'

if (Get-Service $servicename -ErrorAction SilentlyContinue){

}else{

Copy-Item "\\LDN2WS7001\AppDv3" -Destination "C:\Program Files (x86)\ICAP" -Recurse -Force

Start-Sleep -Seconds 10

 
 
 cd "C:\Program Files (x86)\ICAP\AppDv3"

 .\AppDInstallV3.bat /quiet

}