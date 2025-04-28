$username = $null
$CorpDCpass = $null
$CorpCreds = $null
$servers = $null
$output = $null
$output = @()
$servers = Get-Content -Path "C:\temp\appd.txt"

foreach($servername in $servers){
    $FQDNfinal = $servername.Split( "." )[1]
    switch ($FQDNfinal){
        "corp" {
              $username = "corp.ad.tullib.com\CORP PMS"
              $CorpDCpass =  ConvertTo-SecureString -String 'oPiPTvluz2D*3VxOD$Nhlc6lS5q$AMvH' -AsPlainText -Force}
            
         "na" {
              $username = "na.ad.tullib.com\NA PMS"
              $CorpDCpass =  ConvertTo-SecureString -String '#d4RRAmT$lyprF)Tl&!bQ#WDqTXQTXgE' -AsPlainText -Force}
            
          "us"{
              $username = "us.icap.com\US PMS"
              $CorpDCpass =  ConvertTo-SecureString -String 'JGkiIzX4uFzuR*wXosbO*U16NV^5JO6B' -AsPlainText -Force}
            
         "global"{
              $username = "GLOBAL PMS\GBL DA 4"
              $CorpDCpass =  ConvertTo-SecureString -String 'a6P!qTIndu)$kJCga' -AsPlainText -Force}
              
          "lnholdings"{
              $username = "lnholdings.com\LN PMS"
              $CorpDCpass =  ConvertTo-SecureString -String 'iNHWBKF2D&WpudU' -AsPlainText -Force}

          "ad"   {
              $username = "ad.tullib.com\RT TPICAP PMS"
              $CorpDCpass =  ConvertTo-SecureString -String 'XCQ4d@cvJ5EXq@wBktdbXx^mf)ZvWhBX' -AsPlainText -Force}

           "icap"{
               $username = "icap.com\RT ICAP PMS"
               $CorpDCpass =  ConvertTo-SecureString -String 'k5@lBIC9fAVQOjX$Kd(Ex33ApNJf1KAz' -AsPlainText -Force}
       }
$CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$CorpDCpass

$Connection = Test-Connection $servername -Count 2 -Quiet
        if ($Connection -eq $True)  {
            $network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $servername -Credential $CorpCreds -ErrorAction Stop | Where-Object {$_.IPConnectionMetric -ne $null}
            #$dnsclient = $network | select-object @{Name='DNSServerSearchOrder';Expresion={[string]::join(";",($_.DNSServerSearchOrder))}}
            $dnsclient= $Network.DNSServerSearchOrder
            $forwarders = Invoke-Command -ComputerName $servername -Credential $CorpCreds  -ScriptBlock {get-dnsserverforwarder}
            $UseRootHint = $forwarders.UseRootHint
            $timeout = $forwarders.Timeout
            $EnableReordering = $forwarders.EnableReordering
            $ReorderedIPAddress = $forwarders.ReorderedIPAddress
            $features = Get-WindowsFeature -ComputerName $servername -Credential $CorpCreds
            $ADRole = $features | Where-Object installstate -eq installed | Where-Object Name -EQ AD-Domain-Services
            $DNSRole = $features| Where-Object installstate -EQ installed | Where-Object Name -EQ DNS
            if ($ADRole){
                $ADRole = 'Installed'
            }
            Else{
                $ADRole = 'NotInstalled'
            }
            if ($DNS){
                $DNSRole = 'Installed'
            }
            else {
                $DNSRole = 'NotInstalled'
            }
            $obj = New-object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name Computername -value $servername
            $obj | Add-Member -MemberType NoteProperty -Name DNSServer -value $dnsclient
            $obj | Add-Member -MemberType NoteProperty -Name ADServerRole -value $ADRole
            $obj | Add-Member -MemberType NoteProperty -Name DNSServerRole -value $DNSRole
            $obj | Add-Member -MemberType NoteProperty -Name UseRootHint -value $UseRootHint
            $obj | Add-Member -MemberType NoteProperty -Name Timeout -value $timeout
            $obj | Add-Member -MemberType NoteProperty -Name EnableReordering -value $EnableReordering
            $obj | Add-Member -MemberType NoteProperty -Name ReorderedIPAddress -value $ReorderedIPAddress
            $output += $obj
        } 
        else {
            Write-host "$servername is not reachable `r`n" -ForegroundColor Yellow
          }
}
$output | FT -AutoSize