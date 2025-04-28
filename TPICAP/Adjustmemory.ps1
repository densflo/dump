Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
$vCenterInstance = 'ld5pinfvca01.corp.ad.tullib.com'
Connect-VIServer $vCenterInstance -WarningAction SilentlyContinue
$vCenterInstance = 'arkpinfvca01.corp.ad.tullib.com'
Connect-VIServer $vCenterInstance -WarningAction SilentlyContinue
$servers = ("LDN1WS073N01", "LDN2WS073N02")
$Output = $null
$Output = @()
foreach ($server in $servers){
    $VM= get-vm $server
    Shutdown-VMGuest -VM $VM -Confirm:$false > $null
    while ($VM.PowerState -eq "PoweredOn") {
    set-vm -MemoryGB 48
    Start-VM $vm |Wait-Tools
    start-sleep -s 60
    }
    $Connection = Test-Connection $server -Count 2 -Quiet
    if ($Connection -eq $False){
        $Obj = New-Object -TypeName PSOBject
        $Obj | Add-Member -MemberType NoteProperty -Name Servername $VM.Name
        $Obj | Add-Member -MemberType NoteProperty -Name "VM Status"  -Value $VM.PowerState
        $Obj | Add-Member -MemberType NoteProperty -Name "CPU"  -Value $VM.NumCpu
        $Obj | Add-Member -MemberType NoteProperty -Name "Memory"  -Value $VM.MemoryGB
        $Obj | Add-Member -MemberType NoteProperty -Name "MEMhotadd"  -Value $VM.MemoryHotAddEnabled
        $Obj | Add-Member -MemberType NoteProperty -Name "Pingable" -Value "No"
        $Output += $Obj
    }
    else {
        $Obj = New-Object -TypeName PSOBject
        $Obj = New-Object -TypeName PSOBject
        $Obj | Add-Member -MemberType NoteProperty -Name Servername $VM.Name
        $Obj | Add-Member -MemberType NoteProperty -Name "VM Status"  -Value $VM.PowerState
        $Obj | Add-Member -MemberType NoteProperty -Name "CPU"  -Value $VM.NumCpu
        $Obj | Add-Member -MemberType NoteProperty -Name "Memory"  -Value $VM.MemoryGB
        $Obj | Add-Member -MemberType NoteProperty -Name "MEMhotadd"  -Value $VM.MemoryHotAddEnabled
        $Obj | Add-Member -MemberType NoteProperty -Name "Pingable" -Value "Yes"
        $Output += $Obj
    }
}
$Output