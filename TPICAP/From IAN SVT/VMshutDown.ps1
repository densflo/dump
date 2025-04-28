
Connect-VIServer -Server ldnpinfvcs01.eur.ad.tullib.com  -User "corp\srvcDev42VC" -Password "R#2TwaM@"



#Batch 1 
#powerdown Time 19:00 GMT

#batch 2
#powerdown Time 23:00 GMT Application Servers

#Batch 3
#powerdown Time 23:10 GMT SQL Servers

#Batch 4
#powerdown Time 23:20 GMT Domain Controllers

foreach($vmlist1 in (Get-Content -Path C:\temp\Batch1.txt)){
$vm1 = Get-VM -Name $vmlist1
Shutdown-VMGuest -VM $vm1 -Confirm:$false 
}



