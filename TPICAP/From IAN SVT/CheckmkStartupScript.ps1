$servicename = "CheckMkService"

if (Get-Service $servicename -ErrorAction SilentlyContinue){

}else{

Copy-Item "\\LDN2WS7001\CheckMK" -Destination "C:\Program Files (x86)\ICAP" -Recurse -Force

Start-Sleep -Seconds 10

 
 
 cd "C:\Program Files (x86)\ICAP\CheckMK"

 .\check_mk_agent.msi /quiet

}