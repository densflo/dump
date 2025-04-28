function Get-LockoutInfoAndLogoff {
    param(
        [Parameter(Mandatory=$true)]
        [string]$domainName,
        
        [Parameter(Mandatory=$true)]
        [string]$userName,
        
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$cred,
        
        [int]$daysBack = 7
    )
    
    $domain = Get-ADDomain $domainName
    $pdc = $domain.PDCEmulator
    Write-Host "PDC for $domainName is $($pdc)"

    $startDate = (Get-Date).AddDays(-$daysBack)
    $endDate = Get-Date

    $lockout = Get-ADUser -Identity $userName -Properties * | Select-Object Username, accountexpirationdate, accountexpires, accountlockouttime, badlogoncount, padpwdcount, lastbadpasswordattempt, lastlogondate, lockedout, passwordexpired, passwordlastset, pwdlastset | format-list

    if ($lockout.lockedout -eq $true){
        Write-Host 'Account is locked, unlocking account'
        
        try{
        Unlock-ADAccount -Identity $userName -Server $pdc -Credential $cred
        Write-Host 'Unlocking Sucessfull'
        }
        catch{
        Write-Host "Unlock failed"
        }
    
    Write-Host 'Searching for unlock source'

    Invoke-Command -ComputerName $pdc -Credential $cred -ScriptBlock {
        $events = Get-EventLog -LogName Security -InstanceId 4740 -After $using:startDate -Before $using:endDate | Where-Object { $_.Message -match $using:userName }
        if ($events) {
            $output = @()
            foreach ($event in $events) {
                $lockoutSourceRegex = 'Caller Computer Name:\s*(\S+)'
                $lockoutSource = ($event.Message | Select-String -Pattern $lockoutSourceRegex).Matches.Groups[1].Value
                $properties = @{
                    Username = $event.ReplacementStrings[0]
                    TimeGenerated = $event.TimeGenerated
                    DomainController = $event.MachineName
                    LockoutSource = $lockoutSource
                }
                $output += New-Object psobject -Property $properties
            }
            $output | Format-Table Username, TimeGenerated, DomainController, LockoutSource -AutoSize
            
            $lockoutSource = $output[0].LockoutSource
            $sessionId = (query session /server:$lockoutSource | Where-Object { $_ -match $using:userName } | ForEach-Object { $_.Trim() -replace '\s+',',' } | ConvertFrom-Csv).ID
            if ($sessionId) {
                Write-Host "Session ID for user $($using:userName) is $($sessionId)."
                logoff $sessionId /server:$lockoutSource
                Write-Host "User $($using:userName) has been logged off from $($lockoutSource)."
            } else {
                Write-Host "No session found for user $($using:userName) on $($lockoutSource)."
            }
        } else {
            Write-Host "No events found for user $($using:userName) within the past $daysBack days."
        }
    }
}
}
