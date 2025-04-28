$servers = get-content C:\temp\servers.txt
$Results = $null
$Results = New-Object -TypeName System.Collections.ArrayList



function Invoke-DSAScript {
    param (
        [string]$computerName,
        [System.Management.Automation.PSCredential]$credentials
    )

    $command = 'C:\Program Files\Trend Micro\Deep Security Agent\dsa_control.cmd'
    $agentParams = @(
        'dsm://agents.workload.gb-1.cloudone.trendmicro.com:443/',
        'tenantID:BE123086-1CAA-5C3A-2027-3BCB78B797A6',
        'token:9BA0BFE0-65DE-2658-82BB-2AD32ED43100',
        'policyid:562'
    )

    $scriptBlock = {
        param($command, $agentParams)
        Write-Host "unlocking the agent"
        $initialOutput = & $command -r
        Write-Host $computerName $initialOutput
        $response = New-Object -TypeName PSObject -Property @{
            successful = $false
            output     = ""
        }

        if ($initialOutput -match "HTTP Status: 200 - OK") {
            Write-host "$computerName Unlocked, Registering"
            $job = Start-Job -ScriptBlock { param($command, $agentParams) & $command -a $agentParams } -ArgumentList $command, $agentParams
            $output = Receive-Job -Job $job
            Write-Host $output
        }
        elseif ($initialOutput -match "HTTP Status: 403 - Forbidden") {
            Write-host "$computerName Unlocked, Failed, trying passwords"
            $setPasswordOutput = & $command -s 0 -p 'WWIQ7G!fHX$19LQZBZD'
            Write-Host $setPasswordOutput
            $unlockOutput = & $command -r -p 'WWIQ7G!fHX$19LQZBZD'
            Write-Host $unlockOutput
            $job = Start-Job -ScriptBlock { param($command, $agentParams) & $command -a $agentParams } -ArgumentList $command, $agentParams
            $output = Receive-Job -Job $job
            Write-Host $output
        }
        else {
            $response.output = $initialOutput
            return $response
        }
        Write-Host "Waiting for job Completion"
        $result = $job | Wait-Job -Timeout (10 * 60)
        $output = Receive-Job -Job $job
        Write-Host $output
        if ($result -eq $null) {
            $job | Stop-Job
            $response.output = "The process took more than 10 minutes to execute and has been terminated."
        }
        else {
            $output = Receive-Job -Job $job
            $response.output = $output
            if ($output -match "Received a 'Metrics' command from the manager") {
                $response.successful = $true
                Write-Host "$computerName successfully registered"
            }
        }
        return $response
    }
try {
    $remoteJob = Invoke-Command -ComputerName $computerName -Credential $credentials -ScriptBlock $scriptBlock -AsJob -ArgumentList $command, $agentParams
    Wait-Job $remoteJob
    $finalOutput = Receive-Job -Job $remoteJob

}
catch {
    Write-Host "Error: $($_.Exception.Message)"
}
    
    return $finalOutput
}


function set-credential {
    param (
        $computerName
    )

    $FQDN = [net.dns]::GetHostEntry($computername).Hostname
    $FQDNfinal = $FQDN.Split( "." )[1]
    switch -Wildcard ($FQDNfinal) {
        "corp" {
            $AccountName = "corp.ad.tullib.com\CORP PMS"
            $accontPassword = ConvertTo-SecureString -String 'D*Iz5m(8*MRGUgFs%(4xoMyN@ihoUUYa' -AsPlainText -Force
        }
        "ad" {
            $AccountName = "AD.tullib.com\RT TPICAP PMS"
            $accontPassword = ConvertTo-SecureString -String 'KAA3Y2m(KbCNr^TPj^4!hpmKW#jiW3T@' -AsPlainText -Force
        }
        "apac" {
            $AccountName = "apac.ad.tullib.com\APAC PMS"
            $accontPassword = ConvertTo-SecureString -String 'yfw533mnYt6PZ3$XPFQMZ89n(kwq@g#x' -AsPlainText -Force
        }
        "eur" {
            $AccountName = "EUR\EUR PMS"
            $accontPassword = ConvertTo-SecureString -String 'vTzqrb3A9k2QpQQ2VeyA69#dOJtmJjDp' -AsPlainText -Force
        }
        "na" {
            $AccountName = "NA\NA PMS"
            $accontPassword = ConvertTo-SecureString -String 'ehG7BMdU7lY@9x&5Iz#C*Ky@RS$)v@zu' -AsPlainText -Force
        }
        "au" {
            $AccountName = "au.icap.com\AU PMS"
            $accontPassword = ConvertTo-SecureString -String '39#r703&WG5S&45gjDsbTZB33KQ3ksjW' -AsPlainText -Force
        }
        "br" {
            $AccountName = "br.icap.com\BR PMS"
            $accontPassword = ConvertTo-SecureString -String 'Jz3CuxnbBRcXWU' -AsPlainText -Force
        }
        "global" {
            $AccountName = "GLOBAL\GLOBAL PMS"
            $accontPassword = ConvertTo-SecureString -String 'wP9@J2emcuK*ZkHrlJy&c*wRgMczw9!w' -AsPlainText -Force
        }
        "hk" {
            $AccountName = "HK\HK PMS"
            $accontPassword = ConvertTo-SecureString -String 'kL!X^*Cf2f9xP$xFfKMaahzCe%!Ivbi1' -AsPlainText -Force
        }
        "jpn" {
            $AccountName = "JPN\JPN PMS"
            $accontPassword = ConvertTo-SecureString -String '#VVw8bmN*McsSkBu*O0O8JT7PCb(rmo!' -AsPlainText -Force
        }
        "uk" {
            $AccountName = "UK\UK PMS"
            $accontPassword = ConvertTo-SecureString -String 'le7(YKA^d$7mzaD3dpVX2d@4h2@XQkxZ' -AsPlainText -Force
        }
        "us" {
            $AccountName = "US\US PMS"
            $accontPassword = ConvertTo-SecureString -String 'zu*8ARlgN8smReA5CTDR7d7I4TaB@I)$' -AsPlainText -Force
        }
        "lnholdings" {
            $AccountName = "lnholdings.com\LN PMS"
            $accontPassword = ConvertTo-SecureString -String 'B!6rZr(#OclJ7z%' -AsPlainText -Force
        }
        "icap" {
            $AccountName = "icap.com\RT ICAP PMS"
            $accontPassword = ConvertTo-SecureString -String 'JXmHSfb2%cuVXTI^f!u(eMf%7EX&nZBN' -AsPlainText -Force
        }
        "ebdev" {
            $AccountName = 'ebdev.tpebroking.com\EBDEV PMS'
            $accontPassword = ConvertTo-SecureString -String 'A6AMULu#Rw)r&p6)KNufA)OJ6nY^a4L!' -AsPlainText -Force
        }
        "sg" {
            $AccountName = 'sg.icap.com\SG PMS'
            $accontPassword = ConvertTo-SecureString -String '47IIk(t2)3lbR9ZCWzQd9Lpxbls)$Um6' -AsPlainText -Force
        }
        "pvm" {
            $AccountName = 'pvm.co.uk\PVM PMS'
            $accontPassword = ConvertTo-SecureString -String 'n(7WN0oV@vp&Q4@XjUn' -AsPlainText -Force
        }
        
    }
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AccountName, $accontPassword

    return $creds
}




foreach ($server in $servers) {
    Write-Host "Processing server: $server"
    $cred = set-credential -computername $server
    $register = Invoke-DSAScript -computerName $server -credentials $cred

    $Obj = New-Object -TypeName PSOBject
    $Obj | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $server
    $Obj | Add-Member -MemberType NoteProperty -Name "Register" -Value $Register.successful
    $Obj | Add-Member -MemberType NoteProperty -Name "DSA output" -Value $Register.output
    $null = $Results.Add($Obj)

}

$Results