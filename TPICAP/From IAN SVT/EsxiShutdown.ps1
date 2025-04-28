
#Esxi Shutdown


Connect-VIServer -Server ldnpinfvcs01.eur.ad.tullib.com  -User "corp\srvcDev42VC" -Password "R#2TwaM@"

$EsxiList = Get-Content -Path C:\temp\esxilist.txt




foreach ($esxi in $EsxiList){

Stop-VMHost -VMHost $esxi -Confirm:$false

}