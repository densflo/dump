$uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
$uninstallWow6432Node = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$subKeys = Get-ChildItem -Path $uninstallKey 
$subKeysWow6432Node = Get-ChildItem -Path $uninstallWow6432Node 
$subKeys += $subKeysWow6432Node

$count = 0 # initialize count to 0 

foreach ($subKey in $subKeys) {
    $displayName = $subKey.GetValue("DisplayName")
    if ($displayName -like "*Apex*") {
        Start-Process -FilePath 'C:\temp\trend\A1\scut.exe' -ArgumentList "-noinstall" -NoNewWindow -Wait
        $service = Get-Service -ErrorAction SilentlyContinue
        if ($service.Name -isnot [array] -and $service.DisplayName -like "*Trend*") {
            exit 1
        }
    }
    elseif ($displayName -like "Trend Micro Deep Security Agent") {
        $services = @(Get-Service | Where-Object { $_.DisplayName -like "*Trend*" })
        foreach ($service in $services) {
            if ($service.Status -ne "Running") {
                $count = 1 
            }
        }
        if ($count -eq 1) {
            Start-Process -FilePath msiexec -ArgumentList "/i Agent-Core-Windows.msi /qn ADDLOCAL=ALL /l*v `"$env:LogPath\dsa_install.log`"" -Wait -PassThru
            $intallflag = 1
            $services = @(Get-Service | Where-Object { $_.DisplayName -like "*Trend*" })
            foreach ($service in $services) {
                if ($service.Status -ne "Running") {
                    Exit 1
                }
            }
        }
    }
}

if ($intallflag -ne 1){
    Start-Process -FilePath msiexec -ArgumentList "/i Agent-Core-Windows.msi /qn ADDLOCAL=ALL /l*v `"$env:LogPath\dsa_install.log`"" -Wait -PassThru 
}

$ipList = @("10.136.3.46", "10.136.3.47", "10.136.3.48")
$port = 8080

$responseTimes = @{}
foreach ($ip in $ipList) {
    $output = & '.\tcping.exe' $ip $port
    $responseTime = $output.Split(' ')[-2]
    $responseTimes.Add($ip, $responseTime)
}

$lowestIp = $responseTimes.GetEnumerator() | Sort-Object Value | Select-Object -First 1

& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -s -0 -p 'WWIQ7G!fHX$19LQZBZD'
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -r -p 'WWIQ7G!fHX$19LQZBZD'
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -s -0
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -r
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -x dsm_proxy://$lowestIp.name:8080
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -y dsm_proxy://$lowestIp.name:8080
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -a $ACTIVATIONURL "tenantID:BE123086-1CAA-5C3A-2027-3BCB78B797A6" "token:9BA0BFE0-65DE-2658-82BB-2AD32ED43100" "policyid:267"