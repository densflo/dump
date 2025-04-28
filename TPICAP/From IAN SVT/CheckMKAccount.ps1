
$accountName = "CheckMKEsxiUser"
$accountPswd = '8w9Yq?\ZTtcwB6eFY{sjSPEf$K(B%2<E$K'
$accountDescription = "CheckMK Account"
$esxlist = get-content -Path "C:\test.txt"

foreach($esx in $esxlist){
    Connect-VIServer -Server $esx -User root -Password '8Lpd3ttsKgEJAX6LN'
   
    
    Try{
        $account = Get-VMHostAccount -Id $accountName -ErrorAction Stop |
        Set-VMHostAccount -Password $accountPswd -Description $accountDescription 
    }
    Catch{
        $account = New-VMHostAccount -Id $accountName -Password $accountPswd -Description $accountDescription -UserAccount  
    }
    
     Get-Folder -Name root  | New-VIPermission -Principal $account -Role ReadOnly
  
    Disconnect-VIServer -Confirm:$false
}