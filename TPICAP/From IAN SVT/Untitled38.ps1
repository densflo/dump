$esxhost = Get-Content -Path c:\test.txt

foreach ($esx in $esxhost){

Connect-VIServer -Server $esx -User root -Password 8Lpd3ttsKgEJAX6LN

Get-VM -ErrorAction SilentlyContinue | select @{N="esx";E={"$esx"}},name,powerstate | Export-Csv D:\esx\$esx.csv



}


