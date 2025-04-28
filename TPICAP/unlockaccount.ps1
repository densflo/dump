$userName = 'corp pms'
$lockout = Get-ADUser -Identity $userName -Properties LockedOut

if ($lockout.LockedOut -eq $true) {
    Unlock-ADAccount -Identity $userName -Credential $cred
    $startDate = (Get-Date).AddDays(-1)
$endDate = Get-Date
$events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = $startDate; EndTime = $endDate } | Where-Object { $_.Properties[0].Value -eq $userName }

if ($events) {
    $output = @()
    foreach ($event in $events) {
        $lockoutSource = $event.Properties[1].Value
        $properties = @{
            Username         = $event.Properties[0].Value
            TimeGenerated    = $event.TimeCreated
            DomainController = $event.MachineName
            LockoutSource    = $lockoutSource
        }
        $output += New-Object psobject -Property $properties
    }
    $output | Format-Table Username, TimeGenerated, DomainController, LockoutSource -AutoSize

    $uniqueLockoutSources = $output | Select-Object -ExpandProperty LockoutSource -Unique
    foreach ($lockoutSource in $uniqueLockoutSources) {
        $userNameToMatch = $userName
        $sessions = quser /server:$lockoutSource 2>&1 | Where-Object { $_ -imatch "^\s*$userNameToMatch\s" } | ForEach-Object {
                        ($_.Trim() -split '\s+')[2]
        }

                
        foreach ($session in $sessions) {
            logoff $session /server:$lockoutSource
                        
        }
                
       
    }
}
else {
exit
}



}