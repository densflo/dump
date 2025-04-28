function Get-ExchangeQueueInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServerName
    )

    $results = @()
    try {
        $queue = Get-TransportService -Identity $ServerName | Get-Queue
        $queueInfo = [PSCustomObject]@{
            Server = $ServerName
            MessageCount = $queue.MessageCount
            NextHopDomain = $queue.NextHopDomain
            Status = $queue.Status
        }
        $results += $queueInfo
    }
    catch {
        Write-Error $_.Exception.Message
    }

    return $results
}
