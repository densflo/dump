﻿$path = "\\SNGPINFFSH21\Singapore_Department$" #define path to the shared folder

$reportpath ="D:\SGDeptShares.csv" #define path to export permissions report

#script scans for directories under shared folder and gets acl(permissions) for all of them
dir -Recurse $path | where { $_.PsIsContainer } | % { $path1 = $_.fullname; Get-Acl $_.Fullname | % { $_.access | Add-Member -MemberType NoteProperty '.\Application Data' -Value $path1 -passthru }} | Export-Csv $reportpath