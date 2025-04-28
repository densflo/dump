ipconfig /all
$adapter = Get-CimInstance Win32_networkAdapterConfiguration | Where-Object { ($_.IPAddress -ne $null) -and ($_.IPEnabled -eq $true)}


    switch ($adapter.DNSServerSearchOrder[0]) {
        '10.138.36.31' {
            write-host $dns" found"  
            write-host "replacing DNS with NJC1WS0001 10.161.72.10, 10.160.72.10"
            $adapter.DNSServerSearchOrder('10.161.72.10', '10.160.72.10')
        }
        '10.137.36.31' {
            write-host "replacing DNS with NJC1WS0001 10.161.72.10, 10.160.72.10" 
            $adapter.DNSServerSearchOrder('10.161.72.10', '10.160.72.10') 
        }
        '10.138.36.32' {
            write-host "replacing DNS with NJC1WS0001 10.161.72.10, 10.160.72.10" 
            $adapter.DNSServerSearchOrder('10.161.72.10', '10.160.72.10') 
        }
        '10.138.36.18' {
            write-host "replacing DNS with NJC1WS0001 10.161.72.10, 10.160.72.10"
            $adapter.DNSServerSearchOrder('10.161.72.10', '10.160.72.10') 
        }
        '10.138.36.19' {
            write-host "replacing DNS with NJC1WS0001 10.161.72.10, 10.160.72.10"
            $adapter.DNSServerSearchOrder('10.161.72.10', '10.160.72.10') 
        }
        Default { write-host 'DNS address not found' } 
    }




