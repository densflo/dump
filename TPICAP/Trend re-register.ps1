$servers = get-content C:\temp\servers.txt
$Results = $null
$Results = @()
. 'C:\Users\dflores-a\Documents\GitHub\TPICAP\Convert-OutputForCSV.ps1'

function set-credential {
    param (
        $computername
    )

    $FQDN = [net.dns]::GetHostEntry($computername).Hostname
    $FQDNfinal = $FQDN.Split( "." )[1]
    switch -Wildcard ($FQDNfinal) {
        "corp" {
            $AccountName = "corp.ad.tullib.com\CORP PMS"
            $accontPassword = ConvertTo-SecureString -String '&kuFc#)kLUspYq7737s$IfPe@cQv&&fd' -AsPlainText -Force
        }
        "ad" {
            $AccountName = "AD.tullib.com\RT TPICAP PMS"
            $accontPassword = ConvertTo-SecureString -String 'dzbr*YEk6NJEl&7fGgKBNWWlx*nTzA5p' -AsPlainText -Force
        }
        "apac" {
            $AccountName = "apac.ad.tullib.com\APAC PMS"
            $accontPassword = ConvertTo-SecureString -String '3wlfZh*V7s@fb!sWwTejCr41S7ZuF3QJ' -AsPlainText -Force
        }
        "eur" {
            $AccountName = "EUR\EUR PMS"
            $accontPassword = ConvertTo-SecureString -String 'NwSuX@ZH11w&rq4^@zIhvZO@!f!FgdU8' -AsPlainText -Force
        }
        "na" {
            $AccountName = "NA\NA PMS"
            $accontPassword = ConvertTo-SecureString -String '546$ey#YuTdf*Z5&dL%kRJzvW7c$C1(w' -AsPlainText -Force
        }
        "au" {
            $AccountName = "au.icap.com\AU PMS"
            $accontPassword = ConvertTo-SecureString -String '#Owr$1ZNF2Cq^BCZ#4ORI2ECRlQs3Z)9' -AsPlainText -Force
        }
        "br" {
            $AccountName = "br.icap.com\BR PMS"
            $accontPassword = ConvertTo-SecureString -String '9rw#e(A&Q^f8%yEg' -AsPlainText -Force
        }
        "global" {
            $AccountName = "GLOBAL\GLOBAL PMS"
            $accontPassword = ConvertTo-SecureString -String 'qlEl8zHzDDlQojEwM6m$Md3)GGyyfFKL' -AsPlainText -Force
        }
        "hk" {
            $AccountName = "HK\HK PMS"
            $accontPassword = ConvertTo-SecureString -String 'nE7LyTtbBpe#QVB#W7LdVyhd#Bs&4Kdi' -AsPlainText -Force
        }
        "jpn" {
            $AccountName = "JPN\JPN PMS"
            $accontPassword = ConvertTo-SecureString -String 'uomCykNP@Uzgx%P&Eo0Nm7zebBcQ6oBi' -AsPlainText -Force
        }
        "uk" {
            $AccountName = "UK\UK PMS"
            $accontPassword = ConvertTo-SecureString -String 'QRhht0MNfSn&#2k*(1LFKKNNHWpZ%219' -AsPlainText -Force
        }
        "us" {
            $AccountName = "US\US PMS"
            $accontPassword = ConvertTo-SecureString -String 'e$SbPZ13LPWkqU*$NZtN^aHYPb#o^9I#' -AsPlainText -Force
        }
        "lnholdings" {
            $AccountName = "lnholdings.com\LN PMS"
            $accontPassword = ConvertTo-SecureString -String 'r3MqKP@DUIE%&0pbX' -AsPlainText -Force
        }
        "icap" {
            $AccountName = "icap.com\RT ICAP PMS"
            $accontPassword = ConvertTo-SecureString -String 'HFFVRBoPcgp^1GF6y&gf!xZ$bo#xwrg%' -AsPlainText -Force
        }
        "ebdev" {
            $AccountName = 'ebdev.tpebroking.com\EBDEV PMS'
            $accontPassword = ConvertTo-SecureString -String '3%(3!l&WfGGSRq2AblGB6CuS#@UF7O5W' -AsPlainText -Force
        }
        "sg" {
            $AccountName = 'sg.icap.com\SG PMS'
            $accontPassword = ConvertTo-SecureString -String 'TgZ0Nnd#Z)xF(UNlibXdABQs5(3IWTtI' -AsPlainText -Force
        }
        "pvm" {
            $AccountName = 'pvm.co.uk\PVM PMS'
            $accontPassword = ConvertTo-SecureString -String 'n(7WN0oV@vp&Q4@XjUn' -AsPlainText -Force
        }
        
    }
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AccountName, $accontPassword

    return $creds
}

function Invoke-CmdFileOnRemoteServer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$credentials
    )

    $session = New-PSSession -ComputerName $serverName -Credential $credentials

    Invoke-Command -Session $session -ScriptBlock {
        $scriptBlock = {
            & "C:\Program Files\Trend Micro\Deep Security Agent\dsa_control.cmd" -r
            & "C:\Program Files\Trend Micro\Deep Security Agent\dsa_control.cmd" -x dsm_proxy://10.136.3.46:8080
            & "C:\Program Files\Trend Micro\Deep Security Agent\dsa_control.cmd" -y relay_proxy://10.136.3.46:8080
            & "C:\Program Files\Trend Micro\Deep Security Agent\dsa_control.cmd" -a "dsm://agents.workload.gb-1.cloudone.trendmicro.com:443/" "tenantID:BE123086-1CAA-5C3A-2027-3BCB78B797A6" "token:9BA0BFE0-65DE-2658-82BB-2AD32ED43100" "policyid:562"
        }

        $job = Start-Job -ScriptBlock $scriptBlock
        $result = $job | Wait-Job -Timeout (5 * 60)

        if ($result -eq $null) {
            $job | Stop-Job
            Write-Host "Job terminated after 30 minutes."
        } else {
            $output = Receive-Job -Job $job
        }

        $job | Remove-Job
    } -OutVariable Output

    Remove-PSSession $session

}






foreach ($server in $servers) {

    $creds = set-credential -computername $server
    $Connection = Test-Connection $server -count 2
    if ($Connection) {
        $result = Invoke-CmdFileOnRemoteServer -serverName $server -credentials $creds
    }
    else {
        $result = "not reachable"  
    }
    $Obj = New-Object -TypeName PSOBject
    $Obj | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $server
    $Obj | Add-Member -MemberType NoteProperty -Name "CMD Result" -Value $Result
     
    $Results += $Obj
    $result = $null
    
}
$Results | Format-List
$Results | Convert-OutputForCSV | Export-Csv C:\Temp\trendresult.csv

