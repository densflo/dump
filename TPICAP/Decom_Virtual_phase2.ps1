Import-Module VMware.PowerCLI
$user = "CORP\dflores-a"
$pass = ConvertTo-SecureString -String "c@%4Q%PYvBOGp3vM" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($user, $pass)
$vCenter = "njcesxvsvc01"
Connect-VIServer -Server $vCenter -Credential $creds

$vms = @(
"NJCPADPDDC01",
"NJCPADPDDC03",
"NJCPADPCDS01",
"NJCPADPCDS03",
"NJCPADPCDS05",
"NJCPADPCDS07",
"NJCPADPCDS09",
"NJCPADPCDS11",
"NJCPADPCDS13",
"NJCPADPCDS15",
"NJCPADPCDS17",
"NJCPADPCDS19",
"NJCPADPCDS21",
"NJCPADPCDS23",
"NJCPADPCDS25",
"NJCPADPCDS27",
"NJCPADPDMP01",
"NJCPADPENT01",
"NJCPADPENT03",
"NJCPADPENT05",
"NJCPADPENT07",
"NJCPADPETC01",
"NJCPADPUSFI01",
"NJCPADPUSFI03",
"NJCPADPSQLCL101",
"NJCPADPSVR01",
"NJCPADPWEB01",
"NJCPADPADM1",
"NJCPADPADM01",
"NJCPADPDIR01",
"NJCPADPLIQ01"
)

foreach($vmName in $vms) {
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if($vm) {
        if($vm.PowerState -eq "PoweredOn") {
            Shutdown-VMGuest -VM $vm -Confirm:$false
            while($vm.ExtensionData.Runtime.PowerState -eq "poweredOn") {
                Start-Sleep -Seconds 10
                $vm.ExtensionData.UpdateViewData()
            }
        }
        Remove-VM -VM $vm -DeletePermanently -Confirm:$false
    }
}

$report = foreach($vmName in $vms) {
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if($vm) {
        [PSCustomObject]@{
            'VM Name' = $vmName
            'Found in vCenter' = 'Yes'
        }
    } else {
        [PSCustomObject]@{
            'VM Name' = $vmName
            'Found in vCenter' = 'No'
        }
    }
}

$report | Format-Table
Disconnect-VIServer -Server $vCenter -Confirm:$false
