$servicename = "QualysAgent"

if (Get-Service $servicename -ErrorAction SilentlyContinue){

}else{

Copy-Item "\\LDN2WS7001\QualysCloudAgent" -Destination "C:\Program Files (x86)\ICAP" -Recurse -Force

Start-Sleep -Seconds 10

 
 
 cd "C:\Program Files (x86)\ICAP\QualysCloudAgent"

 .\QualysCloudAgentProd.ps1

}