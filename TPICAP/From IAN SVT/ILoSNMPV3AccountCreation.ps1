$user = "root"
$pswd = "8Lpd3ttsKgEJAX6LN"
$esxi = get-content -path D:\dashboard\toping.txt

foreach($esx in $esxi){
    try {
        Connect-VIServer -Server $esx -User $user -Password $pswd -ErrorAction Stop | Out-Null
    }
    catch{
        "Logon failed on $($esx.Name)"
    }
}