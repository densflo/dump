$sampleInterval = 5
$maxSamples = 10

$activeQueueCounter = "\DHCP Server\Active Queue Length"
$discoversCounter = "\DHCP Server\Discovers/sec"
$acksCounter = "\DHCP Server\Acks/sec"
$offersCounter = "\DHCP Server\Offers/sec"
$nacksCounter = "\DHCP Server\Nacks/sec"

$queueCounters = Get-Counter -Counter $activeQueueCounter -SampleInterval $sampleInterval -MaxSamples $maxSamples
$discoversCounters = Get-Counter -Counter $discoversCounter -SampleInterval $sampleInterval -MaxSamples $maxSamples
$acksCounters = Get-Counter -Counter $acksCounter -SampleInterval $sampleInterval -MaxSamples $maxSamples
$offersCounters = Get-Counter -Counter $offersCounter -SampleInterval $sampleInterval -MaxSamples $maxSamples
$nacksCounters = Get-Counter -Counter $nacksCounter -SampleInterval $sampleInterval -MaxSamples $maxSamples

# Calculate Responses/sec by summing Acks/sec, Offers/sec, and Nacks/sec
$responsesCounters = @()
for ($i = 0; $i -lt $maxSamples; $i++) {
    $responsesCounters += New-Object PSObject -Property @{
        Timestamp = $acksCounters.CounterSamples[$i].Timestamp
        ResponsesPerSec = $acksCounters.CounterSamples[$i].CookedValue + $offersCounters.CounterSamples[$i].CookedValue + $nacksCounters.CounterSamples[$i].CookedValue
    }
}

# Output the results
$queueCounters.CounterSamples | Format-Table -Property Timestamp, CookedValue -AutoSize
$discoversCounters.CounterSamples | Format-Table -Property Timestamp, CookedValue -AutoSize
$responsesCounters | Format-Table -Property Timestamp, ResponsesPerSec -AutoSize
