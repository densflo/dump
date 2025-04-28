$TableA = Import-Excel -Path 'C:\Temp\TableA.xlsx' -WorksheetName 'Sheet1'
$TableB = Import-Excel -Path 'C:\Temp\TableB.xlsx' -WorksheetName 'Sheet1'
$TableA | ForEach-Object {
    $MatchValue = $_.'Column A'
    $MatchingRow = $TableB | Where-Object { $_.'Column A' -eq $MatchValue }
    if ($MatchingRow) {
        $TableB = $TableB | Where-Object { $_.'Column A' -ne $MatchValue }
        $TableB += $_
    }
}
Export-Excel -Path 'C:\Temp\TableB.xlsx' -WorksheetName 'Sheet1' -AutoSize -Table $TableB