########## Setup Variables for Script & Remove Spaces from text file ##########

$WorkingDir = "\\10.90.80.243\bulk\windowsKBfix"
$ListLocation = "C:\temp\servers.txt"
$Computers = Get-Content "$ListLocation"
$Transcript = "\\10.90.80.243\bulk\windowsKBfix\transcript.txt"


$CorpDCusername = "corp\inavarrete-a"
$CorpDCpass =  ConvertTo-SecureString -String "I@n@rif121087" -AsPlainText -Force
$CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass

########## Cleanup Text File with List of PCs ##########

(Get-Content "$ListLocation") | Foreach {$_.TrimEnd()} | where {$_ -ne ""} | Set-Content "$ListLocation"


########## Start Logging ##########

Start-Transcript -path $Transcript -append


########## Install Software On PCs ##########

foreach ($Computer in $Computers) {

Write-Host "Processing $Computer"

    try{

        New-Item -ItemType directory -Path "\\$Computer\c$\temp\WindowsKB"
        Copy-Item "\\10.90.80.243\bulk\windowsKBfix\Windows10.0-KB900873-x64.exe" "\\$Computer\c$\temp\windowsKB" -Recurse
       

        
        Write-Host " Installing KB fix on $Computer"
        Invoke-Command -ComputerName $Computer -Credential $CorpCreds  -ScriptBlock {&cmd.exe /c "C:\temp\windowsKB\Windows10.0-KB900873-x64.exe" /q /norestart}
    }catch{"error"}
}

Stop-Transcript


########## Wait 2 Minutes ##########

Start-Sleep -Seconds 120



########## Remove temporary files and folder on each PC ##########

foreach ($Computer in $Computers) {
    Write-Host "Removing Temporary files on $Computer"
    $RemovalPath = "\\$Computer\c$\temp\WindowsKB"
    Get-ChildItem  -Path $RemovalPath -Recurse  | Remove-Item -Force -Recurse
    Remove-Item $RemovalPath -Force -Recurse
    }