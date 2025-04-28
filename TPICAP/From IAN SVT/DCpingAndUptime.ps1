#clear

$Domain = "corp.ad.tullib.com"



# Code
$DCs = Get-ADDomainController -filter * -server "$Domain"   
$AllDCs = $DCs  | foreach {$_.hostname} #| Where-Object {$_.hostname -like "LDNPINFDCG0*"} 

$DCTest =  Foreach($computer in $DCs) {

    if (Test-Connection -ComputerName $computer -Quiet)
    {

    $LastBoot = (Get-WmiObject -Class Win32_OperatingSystem -computername $computer).LastBootUpTime
    $sysuptime = (Get-Date) – [System.Management.ManagementDateTimeconverter]::ToDateTime($LastBoot)

    $days = $sysuptime.Days
    $DaystoHours = ($sysuptime.Days)*24
    $hours = $sysuptime.hours
    $TotalHours = $DaystoHours + $hours
    $TodaysDate = Get-Date

        if($TotalHours -gt '24')
        {
            New-Object -TypeName PSCustomObject -Property @{
                                                            Name = $computer
                                                     'Ping Date' = $TodaysDate
                                                   'Ping Status' = 'Ok'
                                                   'Investigate' = 'No'
                                                        'Uptime' = "$days Days and $hours Hours"
                                                        

}
        }
        else
        {
            New-Object -TypeName PSCustomObject -Property @{
                                                            Name = $computer
                                                     'Ping Date' = $TodaysDate
                                                   'Ping Status' = 'Ok'
                                                   'Investigate' = 'Yes'
                                                        'Uptime' = "$days Days and $hours Hours"
                                                        

}
        }
    }
    else
        {
           New-Object -TypeName PSCustomObject -Property @{
                                                            Name = $computer
                                                     'Ping Date' = $TodaysDate
                                                   'Ping Status' = 'Failed'
                                                   'Investigate' = 'Yes'
                                                        'Uptime' = 'Unable to Reach the Domain Controller'
                                                        

}
        }
}



$DCTest | Export-Csv -Path "D:\Ping\Corp\CorpDCTest$((get-date).ToString("MMddyyyyHHmmss")).csv" -NoTypeInformation