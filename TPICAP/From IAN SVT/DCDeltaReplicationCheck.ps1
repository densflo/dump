$LargestDeltaTreshold = 1
$date = get-date -format "yyyy-MM-dd HHmm"
$repadmin = repadmin /replsum /bydest

[regex]$regex = '\s+(?<DC>\S+)\s+(?<Delta>\S+)\s+(?<fail>\d{1,2}\s)'

[regex]$regex2 = '\s+(?<FAIL>\d{1,2}\S+)\s\-\s+(?<DC>\S+)'

$result = $repadmin | ForEach-Object {

       if ( $_ -match $regex ) {

                $process = "" | Select-Object DC, Delta, fail
                $process.dc = $matches.dc
                $process.Delta = $matches.Delta
                $process.fail = [int]($matches.fail)
		$VdayTime = 0
		$VHourTime = 0
		$VMinutesTime = 0



			if ($process.Delta.contains("d"))  {
				$VdayTime = [int]($process.Delta.substring(0,2))
				$VHourTime = [int]($process.Delta.substring(4,2))
				$VMinutesTime = [int]($process.Delta.substring(8,2))}
			Else {		
				if ($process.Delta.contains("h"))  {
				$VHourTime = [int]($process.Delta.substring(0,2))
				$VMinutesTime = [int]($process.Delta.substring(4,2))}
	
			Else {
			if ($process.Delta.contains("m"))  {
			$VMinutesTime = [int]($process.Delta.substring(0,2))}

			}
	}


$DeltaMinutes = New-TimeSpan -Days $VdayTime -Hours $VHourTime -Minutes $VMinutesTime




if (($DeltaMinutes.days-gt $LargestDeltaTreshold) -or ($process.fail -gt 0)) {

New-Object -TypeName PSCustomObject -Property @{
                                             'DC name' = $process.dc
                                             'Delta Days' = $DeltaMinutes.days 
                                             'Delta hours' = $DeltaMinutes.hours
                                             'Delta Minutes' = $DeltaMinutes.days
                                             'Total Replication Errors' = $process.fail
                                            } 



}


       }


	      Elseif ( $_ -match $regex2 ) {
Write-host "Errors trying to retrieve replication information:"



       }

} |Export-Csv -Path "\\10.90.80.243\dcdiag\Replication\Corp\CorpDCRep$date.csv" -NoTypeInformation