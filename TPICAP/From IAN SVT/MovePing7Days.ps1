$SrcFolder = "D:\Ping\weekly"
$DestFolder = "D:\Ping\Monthly"
$count = 0

 if(-not (Test-Path $DestFolder)){
        New-Item -Path $DestFolder -ItemType Directory
 }
 else{
    Write-Host $DestFolder "Path exists"
 }

 Get-ChildItem -Path $SrcFolder | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-7)} | ForEach-Object {
    
    Write-Host "Moving: " $SrcFolder"\"$_ $_.LastWriteTime to $DestFolder
    Move-Item -Path $SrcFolder"\"$_ -Destination $DestFolder
    $count = $count + 1
 }

 Write-Host "Moved" $count "items."