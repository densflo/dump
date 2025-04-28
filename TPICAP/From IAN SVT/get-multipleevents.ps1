##################################
# Settings Variables
 
##################################
 
$computername = Get-Content -Path "C:\temp\audit.txt"
 
$date = (Get-Date ).ToString('yyyyMMdd')
 
$Query="Select * FROM Win32_NTLogEvent WHERE LogFile=`"Application`" AND EventCode=6005"
 
$ResultList = @()
 
 
$CorpDCusername = "Tradeblade\inavarrete-a"
$CorpDCpass =  ConvertTo-SecureString -String "ZZ!ikwwKP803IcPPS*c" -AsPlainText -Force
$Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass

 
##################################
 
# Getting Event Data
 
#################################
 
foreach ($computer in $computername) 
 
{
 
  write-host "Getting Eventid 21 for " $computer
 
  $TempResult = Get-WmiObject -Query $query -computer $computer -Credential $Creds | Sort-Object TimeGenerated -Descending | select-Object -First 1 
 
  If ($TempResult -ne $null) { 
 
     $TimeGeneratedParsed = (([datetime]::ParseExact(($TempResult.TimeGenerated).split('.')[0],'yyyyMMddHHmmss',$nul).addminutes(($TempResult.TimeGenerated).substring(21)))) 
     $TimeWrittenParsed = (([datetime]::ParseExact(($TempResult.TimeWritten).split('.')[0],'yyyyMMddHHmmss',$nul).addminutes(($TempResult.TimeWritten).substring(21))))
     $TimeGeneratedParsed = $TempResult.ConvertToDateTime($TempResult.TimeGenerated)
     $TimeWrittenParsed = $TempResult.ConvertToDateTime($TempResult.TimeWritten)
     $TempResult | Add-Member -MemberType NoteProperty -Name "TimeGenerated" -Value $TimeGeneratedParsed -Force
     $TempResult | Add-Member -MemberType NoteProperty -Name "TimeWritten" -Value $TimeWrittenParsed -Force

     $ResultList += $TempResult 
 
  }
 
}
 
 
##################################
# Exporting Event Data to Text File
##################################
 
$ResultList | Select-Object __SERVER,EventCode,InsertionStrings,Message,Logfile,TimeGenerated,TimeWritten | export-csv c:\temp\event6005.csv
