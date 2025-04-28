Import-Module VMware.PowerCLI
$user = "CORP\dflores-a"
$pass = ConvertTo-SecureString -String "c@%4Q%PYvBOGp3vM" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($user, $pass)
$vCenter = "njcesxvsvc01.na.ad.tullib.com"
Connect-VIServer -Server $vCenter -Credential $creds
$vms = @(
"NJCPADPDDC02",
"NJCPADPDDC04",
"NJCPADPCDS02",
"NJCPADPCDS04",
"NJCPADPCDS06",
"NJCPADPCDS08",
"NJCPADPCDS10",
"NJCPADPCDS12",
"NJCPADPCDS14",
"NJCPADPCDS16",
"NJCPADPCDS18",
"NJCPADPCDS20",
"NJCPADPCDS22",
"NJCPADPCDS24",
"NJCPADPCDS26",
"NJCPADPCDS28",
"NJCPADPDMP02",
"NJCPADPENT02",
"NJCPADPENT04",
"NJCPADPENT06",
"NJCPADPENT08",
"NJCPADPETC02",
"NJCPADPUSFI02",
"NJCPADPUSFI04",
"NJCPADPSQLCL102",
"NJCPADPWEB02",
"NJCPADPADM02",
"NJCPADPDIR02",
"NJCPADPLIQ02",
"NJCPADPSVR02"
)

$note = "Phase 1 Decom - CHG0115659 - Dennis Jeffrey Flores - May 21, 2023"

$report = foreach($vmName in $vms) {
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if($vm) {
        if($vm.PowerState -eq "PoweredOn") {
            Shutdown-VMGuest -VM $vm -Confirm:$false
            while($vm.ExtensionData.Runtime.PowerState -eq "poweredOn") {
                Start-Sleep -Seconds 10
                $vm.ExtensionData.UpdateViewData()
            }
        }
        $vmStatus = $vm.ExtensionData.Runtime.PowerState
        Set-VM -VM $vm -Description $note -Confirm:$false
        [PSCustomObject]@{
            'VM Name' = $vmName
            'Status' = $vmStatus
            'Found in vCenter' = 'Yes'
        }
    } else {
        [PSCustomObject]@{
            'VM Name' = $vmName
            'Status' = $null
            'Found in vCenter' = 'No'
        }
    }
}

$report | Format-Table
Disconnect-VIServer -Server $vCenter -Confirm:$false
