
Connect-VIServer -Server ldnpinfvcs01.eur.ad.tullib.com  -User "corp\srvcDev42VC" -Password "R#2TwaM@"

#Batch 1

foreach($vmlist1 in (Get-Content -Path C:\temp\Batch1.txt)){
$vm = Get-VM -Name $vmlist1
Start-VM -VM $vm -Confirm:$false
}

Start-Sleep -Seconds 900

#batch 2

##foreach($vmlist2 in (Get-Content -Path C:\TEMP\batch2.txt)){
#$vm = Get-VM -Name $vmlist
#Start-VM -VM $vm -Confirm:$false
#}

#Start-Sleep -Seconds 900

#batch 3

#foreach($vmlist3 in (Get-Content -Path C:\TEMP\batch3.txt)){
#$vm = Get-VM -Name $vmlist
#Start-VM -VM $vm -Confirm:$false
#}

#Start-Sleep -Seconds 900

#Get-VM | select Name,PowerState | export-csv -Path C:\temp\VMPowerupStatus.csv