Get-UDDashboard | Stop-UDDashboard
Get-PSSession -Name * | Remove-PSSession

Get-Module -All | Import-Module -Verbose

$5minuteschedule = New-UDEndpointSchedule -Every 5 -Minute
$Every60Sec = New-UDEndpointSchedule -Every 60 -Minute

$CorpDCusername = "corp\inavarrete-a"
$CorpDCpass =  ConvertTo-SecureString -String "I@n@rif0927" -AsPlainText -Force
$Cache:CorpCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CorpDCusername,$CorpDCpass

$vusername = "corp\srvcDev42VC"
$vpass =  ConvertTo-SecureString -String "R#2TwaM@" -AsPlainText -Force
$Cache:Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $vusername,$vpass
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
$null = Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Scope User -InvalidCertificateAction Ignore  -Confirm:$false

$DCdiagEndpoint = New-UDEndpoint -Schedule $5minuteschedule -Endpoint {
    $Cache:corpDcDiag = @()
    $Cache:corppath = @()
    $Cache:corppath = Get-ChildItem -Path 'D:\DCdiag\CORP' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:corpDcDiag = Import-Csv -LiteralPath $Cache:corppath
    $Cache:corpDCtitle = $Cache:corppath -replace '.*\\' -replace ",.*"

    $Cache:EURDcDiag = @()
    $Cache:EURpath = @()
    $Cache:EURpath = Get-ChildItem -Path 'D:\DCdiag\EUR' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:EURDcDiag = Import-Csv -LiteralPath $Cache:EURpath

    $Cache:APACDcDiag = @()
    $Cache:APACpath = @()
    $Cache:APACpath = Get-ChildItem -Path 'D:\DCdiag\APAC' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:APACDcDiag = Import-Csv -LiteralPath $Cache:APACpath

    $Cache:NADcDiag = @()
    $Cache:NApath = @()
    $Cache:NApath = Get-ChildItem -Path 'D:\DCdiag\NA' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:NADcDiag = Import-Csv -LiteralPath $Cache:NApath

    $Cache:ROOTADcDiag = @()
    $Cache:ROOTADpath = @()
    $Cache:ROOTADpath = Get-ChildItem -Path 'D:\DCdiag\ROOTAD' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ROOTADDcDiag = Import-Csv -LiteralPath $Cache:ROOTADpath

    $Cache:GLOBALDcDiag = @()
    $Cache:GLOBALpath = @()
    $Cache:GLOBALpath = Get-ChildItem -Path 'D:\DCdiag\GLOBAL' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:GLOBALADDcDiag = Import-Csv -LiteralPath $Cache:GLOBALpath

    $Cache:ICAPROOTDcDiag = @()
    $Cache:ICAPROOTpath = @()
    $Cache:ICAPROOTpath = Get-ChildItem -Path 'D:\DCdiag\ICAPROOT' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ICAPROOTDcDiag = Import-Csv -LiteralPath $Cache:ICAPROOTpath

    $Cache:ICAPDcDiag = @()
    $Cache:ICAPpath = @()
    $Cache:ICAPpath = Get-ChildItem -Path 'D:\DCdiag\ICAP' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:ICAPDcDiag = Import-Csv -LiteralPath $Cache:ICAPpath

    $Cache:USDcDiag = @()
    $Cache:USpath = @()
    $Cache:USpath = Get-ChildItem -Path 'D:\DCdiag\US' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:USDcDiag = Import-Csv -LiteralPath $Cache:ICAPpath

    $Cache:CorpDCPing = @()
    $Cache:CorpDCPingPath = @()
    $Cache:CorpDCPingPath = Get-ChildItem -Path 'D:\Ping\Corp' -Recurse  | where {$_.Extension -eq ".csv"} | Sort-Object 'LastWriteTime' -Descending |Select-Object -First 1  |  % {Write-Output $_.FullName }
    $Cache:CorpDCPing = Import-Csv -LiteralPath $Cache:CorpDCPingPath

    $Cache:Link = @()
    $Cache:Link = Import-Csv -Path (Get-ChildItem 'D:\data\link' -Filter '*.csv').FullName   
}
$Schedule = New-UDEndpoint -Schedule $Every60Sec -Endpoint {
    $Cache:EndpointError = $false
    $Cache:vCenterServer = Get-Content -Path D:\dashboard\vcenter.txt 
    if (!($global:DefaultVIServer.Name -eq $Cache:vCenterServer)){
        try{
            $Cache:VCSession = Connect-VIServer -Server $Cache:vCenterServer -Credential $Cache:Creds -ErrorAction SilentlyContinue
            
        }
        catch{
            $Cache:EndpointError = $_.Exception.Message
            $Cache:EndpointError | D:\dashboard\vcentererror.log
        }
    }
    $Cache:ViServerList = $global:DefaultVIServer
}

$pages = @()

$pages += New-UDPage -name "DCdiag" -Content {

New-UDLayout -Columns 1  -Content {
New-UDTabContainer -Tabs {
New-UDTab -Text 'DC Diag Morning Check' -Content {
New-UDColumn -Size 3 {
New-UDTable -Title 'DC Diag CSV files' -Headers @(" "," ") -Endpoint {

$corpcsv = $Cache:corppath -replace '.*\\' -replace ",.*"
$EURcsv = $Cache:EURpath -replace '.*\\' -replace ",.*"
$APACcsv = $Cache:APACpath -replace '.*\\' -replace ",.*"
$NAcsv = $Cache:NApath -replace '.*\\' -replace ",.*"
$ROOTADcsv = $Cache:ROOTADpath -replace '.*\\' -replace ",.*"
$Globalcsv = $Cache:GLOBALpath -replace '.*\\' -replace ",.*"
$ICAPROOTcsv = $Cache:ICAPROOTpath -replace '.*\\' -replace ",.*"
$ICAPcsv = $Cache:ICAPpath -replace '.*\\' -replace ",.*"
$UScsv = $Cache:USpath -replace '.*\\' -replace ",.*"
@{
     'corp' = ($corpcsv)
     'EUR'  = ($EURcsv)
     'APAC'  = ($APACcsv)
     'NA'  = ($NAcsv)
     'ROOT AD'  = ($ROOTADcsv)
     'Global'  = ($Globalcsv)
     'ICAPRoot'  = ($ICAPROOTcsv)
     'ICAP'  = ($ICAPcsv)
     'US'  = ($UScsv)


   }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")


}
}
New-UDColumn -size 4 {

New-UDChart  -Type HorizontalBar -Labels 'Labels'   -Endpoint {  
     #Failed Tests#
     #Corp
     $corpcountfailed = $Cache:corpDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count
     $corpprocessfailed1 = $corpcountfailed -replace  '.*=' 
     $corpfailedfinal = $corpprocessfailed1 -replace '$*}'

     #EUR
     $eurcountfailed = $Cache:EURDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
     $eurprocessfailed1 = $eurcountfailed -replace  '.*=' 
     $eurfailedfinal = $eurprocessfailed1 -replace '$*}'

     #ICAP Root Domain
     $ICAPROOTcountfailed = $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count
     $ICAPROOTprocessfailed1 = $ICAPROOTcountfailed -replace  '.*=' 
     $ICAPROOTfailedfinal = $ICAPROOTprocessfailed1 -replace '$*}'

     #Passed Tests#
     #corp
     $corpcountPassed = $Cache:corpDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $corpprocesspassed1 = $corpcountPassed -replace  '.*=' 
     $corpPassedfinal = $corpprocesspassed1 -replace '$*}'

     #EUR
     $eurcountPassed = $Cache:EURDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $eurprocesspassed1 = $eurcountPassed -replace  '.*=' 
     $eurPassedfinal = $eurprocesspassed1 -replace '$*}'

     #ICAP Root Domain
     $ICAPROOTcountPassed = $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
     $ICAPROOTprocesspassed1 = $ICAPROOTcountPassed -replace  '.*=' 
     $ICAPROOTPassedfinal = $ICAPROOTprocesspassed1 -replace '$*}'

     #Passed with Remarks#
     #Corp
     $corpcountPassedwithremarks = $Cache:corpDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
     $ICAPROOTpassedremarks = $ICAPROOTcountPassedwithremarks -replace  '.*=' 
     $ICAPROOTpassedremarksfinal =  $ICAPROOTpassedremarks -replace '$*}'

     #EUR
     $eurcountPassedwithremarks = $Cache:EURDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
     $eurpassedremarks = $eurcountPassedwithremarks -replace  '.*=' 
     $eurpassedremarksfinal =  $eurpassedremarks -replace '$*}'

     #ICAP Root Domain
     $ICAPROOTcountPassedwithremarks = $Cache:ICAPROOTDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count
     $ICAPROOTpassedremarks = $ICAPROOTcountPassedwithremarks -replace  '.*=' 
     $ICAPROOTpassedremarksfinal =  $ICAPROOTpassedremarks -replace '$*}'

     
    

  

        @(
            [PSCustomObject]@{ 
            'ID' = 'All Domain Test Results' 
            'Passed' = [int]$corpPassedfinal + [int]$eurPassedfinal + [int]$ICAPROOTPassedfinal
            'Failed' = [int]$corpfailedfinal + [int]$eurfailedfinal + [int]$ICAPROOTfailedfinal
            'Passed with Remarks' = [int]$corppassedremarksfinal + [int]$eurpassedremarksfinal + [int]$ICAPROOTpassedremarksfinal
                      }
         ) | Out-UDChartData -LabelProperty ID -Dataset @(
       New-UdChartDataset -Label "Passed" -DataProperty "Passed" -BackgroundColor "green" -HoverBackgroundColor "green" 
       New-UdChartDataset -Label "Failed" -DataProperty "Failed" -BackgroundColor "red" -HoverBackgroundColor "red"
       New-UdChartDataset -Label "Passed with Remarks" -DataProperty "Passed with Remarks" -BackgroundColor "yellow" -HoverBackgroundColor "red"
       
    )
}

}
New-UDColumn -Size 5 {
 New-UdGrid -Title 'DC Connection test' -Headers @("Investigate","Ping Status","Name","Ping Date","Uptime") -Properties @("Investigate","Ping Status","Name","Ping Date","Uptime")  -AutoRefresh -PageSize 10 -Endpoint {
       $Cache:CorpDCPing | Where-Object {$_.investigate -eq 'yes'} | Out-UDGridData
       }
}
}
}
New-UDTabContainer -Tabs{
New-UDTab  -Text 'DC Diag Overview'          -Content {


New-UDColumn -Size 3 {

New-UDTable -Title 'Corp Domain'  -Headers @(" ", " ") -Endpoint {

$corpcountfailed = $Cache:corpDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$corpcountPassed = $Cache:corpDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$corpcountPassedwithremarks = $Cache:corpDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 

$corpprocessfailed1 = $corpcountfailed -replace  '.*=' 
$corpfailedfinal = $corpprocessfailed1 -replace '$*}'

$corpprocesspassed1 = $corpcountPassed -replace  '.*=' 
$corpPassedfinal = $corpprocesspassed1 -replace '$*}'

$corppassedremarks = $corpcountPassedwithremarks -replace  '.*=' 
$corppassedremarksfinal =  $corppassedremarks -replace '$*}'
 @{
                                                       'No. Test Passed' = ($corpPassedfinal)
                                                       'No. Test Failed' = ($corpfailedfinal)
                                                       'No. Test Passed with Remarks' = ($corppassedremarksfinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Corp test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:corpDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Corp test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:corpDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }


New-UDTable -Title 'ICAP Root Domain'  -Headers @(" ", " ") -Endpoint {

$ICAPROOTcountfailed = $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$ICAPROOTcountPassed = $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$ICAPROOTReplicationCountFailed = $Cache:ICAPROOTDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Measure-Object |   select count
$ICAPROOTcountPassedwithremarks = $Cache:ICAPROOTDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 

$ICAPROOTprocessfailed1 = $ICAPROOTcountfailed -replace  '.*=' 
$ICAPROOTfailedfinal = $ICAPROOTprocessfailed1 -replace '$*}'

$ICAPROOTprocesspassed1 = $ICAPROOTcountPassed -replace  '.*=' 
$ICAPROOTPassedfinal = $ICAPROOTprocesspassed1 -replace '$*}'

$ICAPROOTpassedremarks = $ICAPROOTcountPassedwithremarks -replace  '.*=' 
$ICAPROOTpassedremarksfinal =  $ICAPROOTpassedremarks -replace '$*}'

$ICAPROOTfailedReplication = $ICAPROOTReplicationCountFailed -replace  '.*='
$ICAPROOTfailedReplicationFinal = $ICAPROOTfailedReplication -replace '$*}'
 @{
                                                       'No. Test Passed' = ($ICAPROOTPassedfinal)
                                                       'No. Test Failed' = ($ICAPROOTfailedfinal)
                                                       'No. Test Passed with Remarks' = ($ICAPROOTpassedremarksfinal)
                                                       'No. Replication Test Failed' = ($ICAPROOTfailedReplicationFinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ICAP Root test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ICAPROOTDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ICAP Root Passed test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ICAPROOTDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Failed Replications" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ICAP Root Failed Replications Test" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ICAPROOTDcDiag | Where-Object {($_.TestName -eq 'Replications') -and ($_.status -eq 'failed')}   | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

                     }
New-UDColumn -Size 3 {

New-UDTable -Title 'Eur Domain'  -Headers @(" ", " ") -Endpoint {

$eurcountfailed = $Cache:EURDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$eurcountPassed = $Cache:EURDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$eurcountPassedwithremarks = $Cache:EURDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 

$eurprocessfailed1 = $eurcountfailed -replace  '.*=' 
$eurfailedfinal = $eurprocessfailed1 -replace '$*}'

$eurprocesspassed1 = $eurcountPassed -replace  '.*=' 
$eurPassedfinal = $eurprocesspassed1 -replace '$*}'

$eurpassedremarks = $eurcountPassedwithremarks -replace  '.*=' 
$eurpassedremarksfinal =  $eurpassedremarks -replace '$*}'
 @{
                                                       'No. Test Passed' = ($eurPassedfinal)
                                                       'No. Test Failed' = ($eurfailedfinal)
                                                       'No. Test Passed with Remarks' = ($eurpassedremarksfinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "EUR test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:EURDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "Eur test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:EURDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

New-UDTable -Title 'Root AD Domain'  -Headers @(" ", " ") -Endpoint {

$ROOTADcountfailed = $Cache:ROOTADDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$ROOTADcountPassed = $Cache:ROOTADDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$ROOTADcountPassedwithremarks = $Cache:ROOTADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 

$ROOTADprocessfailed1 = $ROOTADcountfailed -replace  '.*=' 
$ROOTADfailedfinal = $ROOTADprocessfailed1 -replace '$*}'

$ROOTADprocesspassed1 = $ROOTADcountPassed -replace  '.*=' 
$ROOTADPassedfinal = $ROOTADprocesspassed1 -replace '$*}'

$ROOTADpassedremarks = $ROOTADcountPassedwithremarks -replace  '.*=' 
$ROOTADpassedremarksfinal =  $ROOTADpassedremarks -replace '$*}'
 @{
                                                       'No. Test Passed' = ($ROOTADPassedfinal)
                                                       'No. Test Failed' = ($ROOTADfailedfinal)
                                                       'No. Test Passed with Remarks' = ($ROOTADpassedremarksfinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ROOTAD test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ROOTADDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "ROOTAD test Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:ROOTADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

                     }
New-UDColumn -Size 3 {

New-UDTable -Title 'NA Domain'  -Headers @(" ", " ") -Endpoint {

$NAcountfailed = $Cache:NADcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$NAcountPassed = $Cache:NADcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$NAcountPassedwithremarks = $Cache:NADcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 

$NAprocessfailed1 = $NAcountfailed -replace  '.*=' 
$NAfailedfinal = $NAprocessfailed1 -replace '$*}'

$NAprocesspassed1 = $NAcountPassed -replace  '.*=' 
$NAPassedfinal = $NAprocesspassed1 -replace '$*}'

$NApassedremarks = $NAcountPassedwithremarks -replace  '.*=' 
$NApassedremarksfinal =  $NApassedremarks -replace '$*}'
 @{
                                                       'No. Test Passed' = ($NAPassedfinal)
                                                       'No. Test Failed' = ($NAfailedfinal)
                                                       'No. Test Passed with Remarks' = ($NApassedremarksfinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "NA test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:NADcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "NA Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:NADcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

New-UDTable -Title 'APAC Domain'  -Headers @(" ", " ") -Endpoint {

$APACcountfailed = $Cache:APACDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$APACcountPassed = $Cache:APACDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$APACcountPassedwithremarks = $Cache:APACDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 

$APACprocessfailed1 = $NAcountfailed -replace  '.*=' 
$APACfailedfinal = $NAprocessfailed1 -replace '$*}'

$APACprocesspassed1 = $APACcountPassed -replace  '.*=' 
$APACPassedfinal = $APACprocesspassed1 -replace '$*}'

$APACpassedremarks = $APACcountPassedwithremarks -replace  '.*=' 
$APACpassedremarksfinal =  $APACpassedremarks -replace '$*}'
 @{
                                                       'No. Test Passed' = ($APACPassedfinal)
                                                       'No. Test Failed' = ($APACfailedfinal)
                                                       'No. Test Passed with Remarks' = ($APACpassedremarksfinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "APAC test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:APACDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "APAC Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:APACDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

                     }
New-UDColumn -Size 3 {

New-UDTable -Title 'GLOBAL Domain'  -Headers @(" ", " ") -Endpoint {

$GLOBALcountfailed = $Cache:GLOBALADDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$GLOBALcountPassed = $Cache:GLOBALADDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$GLOBALcountPassedwithremarks = $Cache:GLOBALADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 

$GLOBALprocessfailed1 = $GLOBALcountfailed -replace  '.*=' 
$GLOBALfailedfinal = $GLOBALprocessfailed1 -replace '$*}'

$GLOBALprocesspassed1 = $GLOBALcountPassed -replace  '.*=' 
$GLOBALPassedfinal = $GLOBALprocesspassed1 -replace '$*}'

$GLOBALpassedremarks = $GLOBALcountPassedwithremarks -replace  '.*=' 
$GLOBALpassedremarksfinal =  $GLOBALpassedremarks -replace '$*}'
 @{
                                                       'No. Test Passed' = ($GLOBALPassedfinal)
                                                       'No. Test Failed' = ($GLOBALfailedfinal)
                                                       'No. Test Passed with Remarks' = ($GLOBALpassedremarksfinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "GLOBAL test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:GLOBALADDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "GLOBAL Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:GLOBALADDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

New-UDTable -Title 'US Domain'  -Headers @(" ", " ") -Endpoint {

$UScountfailed = $Cache:USDcDiag | Where-Object {$_.status -eq 'failed'}  | Measure-Object |   select count 
$UScountPassed = $Cache:USDcDiag | Where-Object {$_.status -eq 'Passed'}  | Measure-Object |   select count
$UScountPassedwithremarks = $Cache:USDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Measure-Object |   select count 

$USprocessfailed1 = $UScountfailed -replace  '.*=' 
$USfailedfinal = $USprocessfailed1 -replace '$*}'

$USprocesspassed1 = $UScountPassed -replace  '.*=' 
$USPassedfinal = $USprocesspassed1 -replace '$*}'

$USpassedremarks = $UScountPassedwithremarks -replace  '.*=' 
$USpassedremarksfinal =  $USpassedremarks -replace '$*}'
 @{
                                                       'No. Test Passed' = ($USPassedfinal)
                                                       'No. Test Failed' = ($USfailedfinal)
                                                       'No. Test Passed with Remarks' = ($USpassedremarksfinal)

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
} 
New-UDButton -text "failed" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "US test Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:USDcDiag | Where-Object {$_.status -eq 'failed'}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }
New-UDButton -text "Passed with remarks" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {


                                         New-UDTable -Title "US Passed Failed" -Headers @("ServerName","TestName","Status","Information") -Endpoint {

                                         $Cache:USDcDiag | Where-Object {($_.status -eq 'Passed') -and ($_.Information -ne "$null")}  | Out-UDTableData -Property @("ServerName","TestName","Status","Information")

                                         }
                                        }
                                         
                                       }
                                      }

                     }

}


                 }


 }
}
$pages += New-UDPage -name "SVT" -Content {


New-UDLayout -Columns 2 -Content {

New-UDColumn -SmallSize 3 {
                           
                         New-UDInput  -Title "Test Server Connection"  -Endpoint{ param($servercheck) 
                                                              
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {
                                         New-UDTable -Title "$servercheck Ping" -AutoRefresh  -Headers @("Name","Ping Status","FQDN") -Endpoint {

                                   $ping = if(Test-Connection -ComputerName $servercheck -Quiet -Count 1) {
                                            New-Object -TypeName PSCustomObject -Property @{
                                             Name = $servercheck
                                            'Ping Status' = 'Ok'
                                            'FQDN' = [net.dns]::GetHostEntry($servercheck).Hostname
                                                }
                                                    } else {
                                                                New-Object -TypeName PSCustomObject -Property @{
                                                                Name = $servercheck
                                                               'Ping Status' = 'Failed'
                                                               'FQDN' = [net.dns]::GetHostEntry($servercheck).Hostname
                                                                } 
                                                                 } 

                                                    $ping  | Out-UDTableData -Property @("Name","Ping Status","FQDN")
                                                                    } 

                                                                        
                                            
                                            
                                            

                                         }
                                         }
                                         } -SubmitText "Test"
                           
                                           
                           

                          }

New-UDColumn -SmallSize 3 {

                        New-UDInput  -Title "Check File Share Access" -endpoint{param($FilePath) 
                                                              
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {
                                         New-UDTable -Title "$FilePath Access Permission" -AutoRefresh  -Headers @("IdentityReference","AccessControlType") -Endpoint {

                              

                                                    (Get-Acl -path $FilePath).Access | Select  @{N="IdentityReference";E={[string]$_.IdentityReference}},@{N="AccessControlType";E={[string]$_.AccessControlType}}    | Out-UDTableData -Property @("IdentityReference","AccessControlType")
                                                                    } 

                                                                        
                                            
                                            
                                            

                                         }
                                         }
                                         } -SubmitText "Check"


}

New-UDColumn -LargeSize 12 {
                                                            
                             
                             New-UDInput   -Title "Windows Server Login Details"   -Content {
       
                                New-UDInputField -Type textbox -Name ServerName -Placeholder 'Server Name'
                                New-UDInputField -Type textbox -Name UserName -Placeholder 'User Name with domain'
                                New-UDInputField -Type password -Name Password -Placeholder 'Password'
       
       
       } -SubmitText "Connect" -Endpoint{
       
                        Param($ServerName,$username,$password )


                        $pass =  ConvertTo-SecureString -String $password -AsPlainText -Force
                        $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$pass
                        


                        New-UDInputAction  -Content{

                               New-UDCard -Title "$ServerName Health Details" -TitleAlignment center  -Content {
                               
                                      

                                    }
                               
                            New-UDTabContainer -Tabs {
                            
                             New-UDTab -Text 'Server Info'  -Content {                          
	                           New-UDColumn -Size 3 {  
                                                       New-UDTable -Title  "Server Information" -Headers @(" ", " ") -Endpoint {
                                                       $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                    @{
                                                       'Computer Name' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).Name
                                                       'Operating System' = (Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem).Caption
                                                       'Domain' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).Domain
                                                       'Physical Memory' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).TotalPhysicalMemory / 1GB | ForEach-Object { "$([Math]::Round($_, 2)) GBs " }
                                                       'Model' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).Model
                                                       'Manufacturer' = (Get-CimInstance -CimSession $session -ClassName win32_computersystem).Manufacturer

                                                         }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
                                                      }
                                                       New-udtable -Title  "$ServerName CPU and Mem Utilization" -AutoRefresh -Headers @("CPU %","Memory %")-Endpoint{ 
                                                       
                                                       $Array = @()
 

                                                       $Check = $Processor = $ComputerMemory = $RoundMemory = $Object = $null
                                                       $Servername = $Servername.trim()
 
    
                                                       # Processor utilization
                                                       $Processor = (Get-WmiObject -ComputerName $Servername -Class win32_processor -Credential $creds -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average | Select-Object Average).Average
 
                                                       # Memory utilization
                                                       $ComputerMemory = Get-WmiObject -ComputerName $Servername -Credential $creds -Class win32_operatingsystem -ErrorAction Stop
                                                       $Memory = ((($ComputerMemory.TotalVisibleMemorySize - $ComputerMemory.FreePhysicalMemory)*100)/ $ComputerMemory.TotalVisibleMemorySize)
                                                       $RoundMemory = [math]::Round($Memory, 2)
         
                                                       # Creating custom object
                                                       $Object = New-Object PSCustomObject
                                                       $Object | Add-Member -MemberType NoteProperty -Name "CPU %" -Value $Processor
                                                       $Object | Add-Member -MemberType NoteProperty -Name "Memory %" -Value $RoundMemory
 
        
                                                       $Array += $Object
    
                                                       $Array | Out-UDTableData -Property @("CPU %","Memory %")
                                                       
                                                       } 
                                                       New-UDTable -Title  "$ServerName UpTime" -AutoRefresh -Headers @('Last Boot','Uptime') -Endpoint {

                                                           $userSystem = Get-WmiObject win32_operatingsystem -ComputerName $ServerName -Credential $creds -ErrorAction SilentlyContinue 
                                                           
                                                           $sysuptime= (Get-Date) - $userSystem.ConvertToDateTime($userSystem.LastBootUpTime)
                                                           $lastboot = ($userSystem.ConvertToDateTime($userSystem.LastBootUpTime) )
                                                           $uptime = ([string]$sysuptime.Days + " Days " + $sysuptime.Hours + " Hours " + $sysuptime.Minutes + " Minutes" ) 
                                                           $propHash = [ordered]@{
                                                                  
                                                                BootTime     = $lastboot 
                                                                Uptime       = $Uptime
                                                           
                                                               }
                                                            $objComputerUptime = New-Object PSOBject -Property $propHash 
                                                            $objComputerUptime  | Out-UDTableData -Property @("BootTime","Uptime")
                         
                                                               }
                                                       New-UDTable -Title  "APPD Service Monitoring" -AutoRefresh -Headers @("Name","StartMode","State","Status") -Endpoint {
                           $AppdAgent        = if (Get-WMIObject -Query "select * from win32_service where name='Appdynamics Machine Agent'" -computer $ServerName -Credential $creds){
                                             Get-WMIObject -Query "select * from win32_service where name='Appdynamics Machine Agent'" -ComputerName $ServerName -Credential $creds |select name,startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Name      = "Appdynamics Machine Agent"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} }
                           $SnareAgent       = if (Get-WMIObject -Query "select * from win32_service where name='Snare'"                     -computer $ServerName -Credential $creds){
                                             Get-WMIObject -Query "select * from win32_service where name='Snare'" -ComputerName $ServerName -Credential $creds |select name,startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Name      = "Snare"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} }
                           $NTListenerAgent  = if (Get-WMIObject -Query "select * from win32_service where name='tmlisten'"                  -computer $ServerName -Credential $creds){
                                             Get-WMIObject -Query "select * from win32_service where name='tmlisten'" -ComputerName $ServerName -Credential $creds|select @{N="Name";E={"NT Listener"}},startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Name      = "NT Listener"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} }
                           $NTScanAgent      = if (Get-WMIObject -Query "select * from win32_service where name='ntrtscan'"                  -computer $ServerName -Credential $creds){
                                             Get-WMIObject -Query "select * from win32_service where name='ntrtscan'"                        -Computer $ServerName -Credential $creds |select @{N="Name";E={"NT Real Time Scan"}},startmode,state,status

                                                              
                                                    } else { New-Object -TypeName PSObject -Property @{Name      = "NT Real Time Scan"
                                                                                                       startmode = ''
                                                                                                       state     = ''
                                                                                                       status    = 'Not Installed'} }


                                                                                                
                                                                        $AppdAgent,$SnareAgent,$NTListenerAgent,$NTScanAgent | Out-UDTableData -Property @("Name","StartMode","State","Status")

                                                               }
                                                       New-UDButton -text "More Services" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDHeading -Content {

                                         New-UDInput -Title "Stop A Service" -Content {
                                           
                                            New-UDInputField -Type textbox -Name ServiceName -Placeholder 'Service Name'
                                         
                                           } -SubmitText "Stop" -Endpoint {
                                               Param($servicename)

                                              $sess = New-PSSession -ComputerName $servername -Credential $creds
                                              $scriptBlockStop = { param ($service)
     
                                                             Stop-Service -Name $service
                                                             }
                                                 
                                                 

                                               Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop -ArgumentList "$servicename"
                                                                          
                                               Show-UDToast -Message "successfully Stopped $servicename on $servername" -BackgroundColor green -Duration 10000
                                                                          
                                                                          

                                              Remove-PSSession -Session $sess
                                           
                                           
                                           
                                           }

                                         New-UDInput -Title "Start A Service" -Content {
                                           
                                            New-UDInputField -Type textbox -Name ServiceName -Placeholder 'Service Name'
                                         
                                           } -SubmitText "Start" -Endpoint {
                                               Param($servicename)

                                              $sess = New-PSSession -ComputerName $servername -Credential $creds
                                              $scriptBlockStart = { param ($service)
     
                                                             Start-Service -Name $service
                                                             }
                                                 
                                                 

                                               (Invoke-Command -Session $sess -ScriptBlock $scriptBlockStart -ArgumentList "$servicename")
                                                                          
                                               Show-UDToast -Message "successfully Started $servicename on $servername" -BackgroundColor green -Duration 10000
                                                                          
                                                                          

                                                Remove-PSSession -Session $sess
                                           
                                           
                                           
                                           }

                                         New-UDTable -Title "$servername Services" -Headers @("name","StartMode","State","Status") -Endpoint {

                                         Get-WmiObject -ComputerName $servername -Credential $creds -Class Win32_Service | select name, startmode, state, status | sort state | Out-UDTableData -Property @("name","StartMode","State","Status")

                                         }
                                        }
                                         
                                       }
                                      }
                                                       New-UDTable -Title  "Network Details"  -Headers @("IPAddress","SubnetMask","Gateway","DNSServers","MACAddress") -Endpoint {

                                                       $Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ServerName -Credential $creds -EA Stop | ? {$_.IPEnabled}

                                                                    $IPAddress  = $Network.IpAddress[0]            
                                                                   $SubnetMask  = $Network.IPSubnet[0]            
                                                                $DefaultGateway = [string]$Network.DefaultIPGateway            
                                                                   $DNSServers  = $Network.DNSServerSearchOrder            
                                                                 $IsDHCPEnabled = $false            
                                                                             If($network.DHCPEnabled) {            
                                                                             $IsDHCPEnabled = $true            
                                                                                                    }            
                                                                   $MACAddress  = $Network.MACAddress            
                                                                   $OutputObj  = New-Object -Type PSObject                        
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name Gateway -Value $DefaultGateway
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value $DNSServers            
                                                                   $OutputObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress            
                                                                   $OutputObj | Out-UDTableData -Property @("IPAddress","SubnetMask","Gateway","DNSServers","MACAddress")} 
                                                           
                                                                    }        
			                   New-UDColumn -Size 3 {  
                                                       New-UdMonitor -Title "Disk Perfomance" -Type Line -AutoRefresh -RefreshInterval 5 -ChartBackgroundColor @("#80962F23","#8014558C",'#80FF6B63') -ChartBorderColor @('#FFFF6B63','#80962F23','#82C0CFA' ) -Label @('Avg Disk Queue','Current Disk Queue','Read') -Endpoint { 
                                                       Out-UDMonitorData -Data @(

                                                       Get-Counter -ComputerName $ServerName '\PhysicalDisk(0 C:)\Avg. Disk Queue Length'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue  
                                                       Get-Counter -ComputerName $ServerName '\PhysicalDisk(0 C:)\Current Disk Queue Length'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue 
                                                       Get-Counter -ComputerName $ServerName '\PhysicalDisk(0 C:)\\PhysicalDisk(0 C:)\% Disk Read Time'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue        
                                                                ) 
		                                                     }
                                                       New-UDChart -Title "C Disk Space"  -Type Doughnut  -Endpoint {  
                                                           try {
                                                                $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                 
                                                                Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk  | Where-Object {$_.DriveType -eq '3'} | Select-Object -First 3 -Property DeviceID,Size,FreeSpace | ForEach-Object {
                                                                @([PSCustomObject]@{
                                                                                    Label = "Used Space"
                                                                                    Data = [Math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2);
                                                                                      },
                                                                  [PSCustomObject]@{
                                                                                    Label = "Free Space"
                                                                                    Data = [Math]::Round($_.FreeSpace / 1GB, 2);
                                                                                                                           }) | Out-UDChartData -DataProperty "Data" -LabelProperty "Label" -BackgroundColor @("#80FF6B63","#8028E842") -HoverBackgroundColor @("#80FF6B63","#8028E842") -BorderColor @("#80FF6B63","#8028E842") -HoverBorderColor @("#F2675F","#68e87a")
                                                                                        }
                                                                                       }
                                                            catch {
                                                                    0 | Out-UDChartData -DataProperty "Data" -LabelProperty "Label"
                                                                     }
                                                                                                                                 }
                                                       New-UDChart -Title "D Disk Space"  -Type Doughnut  -Endpoint {  
                                                           try {
                                                                $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                 
                                                                Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk  | Where-Object {$_.DriveType -eq '3'} | Select-Object -Skip 1 -Property DeviceID,Size,FreeSpace | ForEach-Object {
                                                                @([PSCustomObject]@{
                                                                                    Label = "Used Space"
                                                                                    Data = [Math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2);
                                                                                      },
                                                                  [PSCustomObject]@{
                                                                                    Label = "Free Space"
                                                                                    Data = [Math]::Round($_.FreeSpace / 1GB, 2);
                                                                                                                           }) | Out-UDChartData -DataProperty "Data" -LabelProperty "Label" -BackgroundColor @("#80FF6B63","#8028E842") -HoverBackgroundColor @("#80FF6B63","#8028E842") -BorderColor @("#80FF6B63","#8028E842") -HoverBorderColor @("#F2675F","#68e87a")
                                                                                        }
                                                                                       }
                                                            catch {
                                                                    0 | Out-UDChartData -DataProperty "Data" -LabelProperty "Label"
                                                                     }
                                                                                                                                 }
                                                       New-UDTable -Title "$ServerName Drives" -Headers @("Drive","FreeSpace GB","Total Space GB","Free %") -Endpoint {
                                                       Get-WmiObject win32_logicaldisk -ComputerName $Servername -Credential $creds  -ErrorAction SilentlyContinue | Where-Object {$_.DriveType -eq '3'}  | Select-Object deviceID,@{n="FreeSpace";e={ [Math]::truncate($_.FreeSpace / 1GB)}},@{n="size";e={ [Math]::truncate($_.Size / 1GB)}},@{L='Free %';E={($_.FreeSpace/$_.size).tostring("P")}} | Out-UDTableData -Property @("DeviceID","FreeSpace","size","free %")}
                                                       New-UDTable -Title "$ServerName Paging Info" -AutoRefresh -Headers @("Name","Size","PeakUsage GB","CurrentUsage GB") -Endpoint {
                                                                  $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                                    
                                                                                Get-CimInstance -CimSession $session -ClassName win32_pagefileusage | select name,@{n="AllocatedBaseSize GB";Expression = {[math]::round($_.AllocatedBaseSize / 1KB, 2)}},@{n="PeakUsage GB";Expression = {[math]::round($_.PeakUsage / 1KB, 2)}},@{n="CurrentUsage GB";Expression = {[math]::round($_.CurrentUsage / 1KB, 2)}} | Out-UDTableData -Property @("Name","AllocatedBaseSize GB","PeakUsage GB","CurrentUsage GB")



                                                                                 }
                                                        


                                                             }
                               New-UDColumn -Size 3 {
                                                        New-UdMonitor -Title "CPU (% processor time)" -Type Line -DataPointHistory 20 -AutoRefresh -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                                                        Get-Counter -ComputerName $ServerName '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
		                                                     }
                                                        New-UDTable -Title "$ServerName CPU Core Usage" -AutoRefresh -Headers @("Logical Core","Usage %") -Endpoint{

                                                        $res = Get-WmiObject -ComputerName $servername -Credential $creds -Query "select Name, PercentProcessorTime from Win32_PerfFormattedData_PerfOS_Processor" | Where-Object {$_.name -notmatch '_total' } |sort name

                                                        foreach ($single in $res){
                                                                New-Object pscustomobject -Property @{
    
                                                                 cookedvalue = $single.PercentProcessorTime
                                                                 name = $single.Name
                                                                                   } | Out-UDTableData -Property @("Name","cookedvalue")
                                                                   } 

                                                          }
                                                        New-UDTable -Title "$ServerName Top 10 CPU process" -AutoRefresh -Headers @("Name","PercentProcessorTime") -Endpoint {
                                                       
                                                                gwmi -computername $ServerName Win32_PerfFormattedData_PerfProc_Process -Credential $creds|Where-Object {$_.name -notmatch '_total|idle|svchost#'} |sort PercentProcessorTime -desc | select Name,PercentProcessorTime | Select -First 10 | Out-UDTableData -Property @("Name","PercentProcessorTime")

                                                       }
                                                       
                                                       }
                               New-UDColumn -Size 3 {  
                                                       New-UdMonitor -Title "Memory Performance" -Type Line  -AutoRefresh -RefreshInterval 5 -ChartBackgroundColor @("#80962F23","#8014558C",'#80FF6B63') -ChartBorderColor @('#FFFF6B63','#80962F23','#82C0CFA' ) -Label @('Commit','Available','Faults/sec') -Endpoint { 
                                                       Out-UDMonitorData -Data @(

                                                       Get-Counter -ComputerName $ServerName '\memory\% committed bytes in use'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue  
                                                       Get-Counter -ComputerName $ServerName '\memory\Available Mbytes'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
                                                       Get-Counter -ComputerName $ServerName '\Memory\Cache Faults/sec'  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
                                                                
                                                                ) 
		                                                     }
                                                       New-UDChart -Title "Physical memory Usage" -AutoRefresh -Type Doughnut -Endpoint {  
                                                                 $session = New-CimSession -ComputerName $ServerName -Credential $creds
                                                                
                                                                 
                                                                Get-CimInstance -CimSession $session -ClassName win32_operatingsystem   | select -Property TotalVisibleMemorySize, FreePhysicalMemory | ForEach-Object {
                                                                @([PSCustomObject]@{
                                                                                    Label = "Used Memory /GB"
                                                                                    Data = [Math]::Round(($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / 1MB,2);
                                                                                      },
                                                                  [PSCustomObject]@{
                                                                                    Label = "Free Memory /GB"
                                                                                    Data = [Math]::Round($_.FreePhysicalMemory / 1MB,2);
                                                                                                                           }) | Out-UDChartData -DataProperty "Data" -LabelProperty "Label" -BackgroundColor @("#80FF6B63","#8028E842") -HoverBackgroundColor @("#80FF6B63","#8028E842") -BorderColor @("#80FF6B63","#8028E842") -HoverBorderColor @("#F2675F","#68e87a")
                                                                                        }
                                                                                       
                                                            
                                                                                                                                 }
                                                       New-udtable -Title  "$ServerName Top 10 Memory process " -AutoRefresh -Headers @("Name","Private Memory(GB)") -Endpoint {
                                                       
                                                       gwmi -computername $ServerName -Credential $creds Win32_Process | Sort WorkingSetSize -Descending | Select Name,@{n="Private Memory(GB)";Expression = {[math]::round($_.WorkingSetSize / 1GB, 2)}} | Select -First 10 | Out-UDTableData -Property @("Name","Private Memory(GB)")
                                                       
                                                       }
                                                       
                                                       
                                                       }
                                                       }
                                                                    
                             New-UDTab -Text 'Events' -Content {
                                                                      
                                                                      New-UDGrid -Title "$servername System and Application events for past 24 hours" -PageSize 30 -Headers @("ProviderName","TimeCreated","Id","LevelDisplayName","Message") -Properties @("ProviderName","TimeCreated","Id","LevelDisplayName","Message") -Endpoint {
                                                                      
                                                                      
                                                                                                    $days = (Get-Date).AddHours(-24)
                                                                                                    $range = $days.ToShortDateString();


                                                                                          Get-Winevent -ComputerName $servername -Credential $creds -FilterHashtable @{LogName="System","Application"; Level=1,2,3,4; startTime=$range} | select providername, TimeCreated, Id, LevelDisplayName, Message   | Out-UDGridData
                                                                      
                                                                      
                                                                                                                               } 
                                                                     
                                                                     }

                                                       }
		   }
			                                                  
          }
	     }
        }                     
       }
$pages += New-UDPage -name "VMware Morning Checks EMEA" -Content {

              
 New-UDLayout -Columns 1 -Content { 
 New-UDColumn -LargeSize 12 {

                        
                         New-UDCard -Title "EMEA Vcenter Health Details" -TitleAlignment center  -Content {
                               
                                      

                                    }
                         New-UDTabContainer -Tabs {



                           New-UDTab -Text 'LDNPINFVCA01'      -Content {
                           
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LDNPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LDNPINFVCA01 | Select @{N="Vcenter";E={"LDNPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                New-UDTable  -Title "Snapshot More Than 3 days old"  -Headers @('VM','Name',’SizeGB’,'Created')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    $vms = get-vm -Server LDNPINFVCA01

                                    $result =  foreach ($vm in $vms){
                                    
                                     Get-Snapshot -vm $vm | Where {$_.Created -lt (Get-Date).AddDays(-3)} | Select-Object  @{N="VM";E={[string]$_.VM}}, Name,@{Name=’SizeGB’;Expression={[math]::Round($_.SizeGB,2)}}, Created 

                                     }
                                    
                                    $result | Out-UDTableData -Property @('VM','Name',’SizeGB’,'Created')
                                    

                                 
                                 }
                               
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Alarms and Config Issues" -Headers @('Name','NumConfigIssues','NumAlarms') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                            Get-View -Server LDNPINFVCA01 -ViewType HostSystem -Property Name,TriggeredAlarmState,ConfigIssue | ?{$_.TriggeredAlarmState -or $_.ConfigIssue} | `
                                                                                                                                select name, 
                                                                                                                                @{n="NumConfigIssues"; e={($_.ConfigIssue | Measure-Object).Count}},
                                                                                                                                @{n="NumAlarms"; e={($_.TriggeredAlarmState | Measure-Object).Count}} | Out-UDTableData -Property @('Name','NumConfigIssues','NumAlarms')
                           
                              
                           }
                           New-UDTable  -Title "Host Alarms" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LDNPINFVCA01 -ViewType HostSystem -Property Name,OverallStatus,ConfigIssue
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.ConfigIssue -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.ConfigIssue) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           }
                           New-UDTable  -Title "Host Config Issues" -Headers @('Name','Message') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                           $HostsViews = Get-View -Server LDNPINFVCA01 -ViewType HostSystem 
$hostcialarms = $HostsViews | Where-Object {$_.ConfigIssue -ne "{}"}

$hostcialarms = @()
foreach ($HostsView in $HostsViews | Where-Object {$_.Summary.Runtime.ConnectionState -eq 'connected'}) {
    if ($HostsView.ConfigIssue) {
        $HostConfigIssues = $HostsView.ConfigIssue
        Foreach ($HostConfigIssue in $HostConfigIssues) {
            $Details = "" | Select-Object Name, Message
            $Details.Name = $HostsView.name
            $Details.Message = $HostConfigIssue.FullFormattedMessage
            $hostcialarms += $Details
        }
    }
}

$hostcialarms | Sort-Object name | Out-UDTableData -Property @('Name','Message')

                            

                           
                           }
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost -Server LDNPINFVCA01){

                                $hs = Get-View -Server LDNPINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


                         Function Get-TriggeredAlarms {
  	                       param (
  		                    $vCenter = $(throw "A vCenter must be specified.")
  	                          )

                            
  		                       $vc =  $vCenter
  	                        

                            
  	                        $rootFolder = Get-Folder -Server $vc "Datacenters" 

                            foreach ($ta in $rootFolder.ExtensionData.TriggeredAlarmState) {
  		                            $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  		                            $alarm.VC = $vCenter
  		                            $alarm.Alarm = (Get-View -Server $vc $ta.Alarm).Info.Name
  		                            $entity = Get-View -Server $vc $ta.Entity
  		                            $alarm.Entity = (Get-View -Server $vc $ta.Entity).Name
  		                            $alarm.EntityType = (Get-View -Server $vc $ta.Entity).GetType().Name
  		                            $alarm.Status = [string]$ta.OverallStatus
  		                            $alarm.Time = $ta.Time 
  		                            $alarm.Acknowledged = $ta.Acknowledged
  		                            $alarm.AckBy = $ta.AcknowledgedByUser
  		                            $alarm.AckTime = $ta.AcknowledgedTime
  		                            $alarm
  	                                 }
  	
                                    }

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter LDNPINFVCA01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }
                           New-UDButton -text "VMs Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {

        New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
            $VMs = Get-VM -Server LDNPINFVCA01 | Where {$_.PowerState -eq "PoweredOn"}
            New-UDLayout -Columns 3 -Content {
                
                Foreach($VM in $VMs){

                    New-UDcard -Title ($vm.Name) -TextAlignment center -size small -Content {
                        
                        New-UDColumn -Size 6 {
                         New-UDHeading -Text "Memory"           
                         New-UDNivoChart -Id 'MemorChart' -Pie  -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used Memory'
                                value = [int]($vm | Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free Memory'
                                value = [int](100 - ($vm| Get-Stat -Stat mem.usage.average -Realtime -maxsamples 1).value )
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                       }
                       New-UDColumn -Size 6 {
                         New-UDHeading -text "CPU"           
                         New-UDNivoChart -Id 'CPUChart' -Pie  -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
                            @{
                                id = 'Used'
                                label = 'Used CPU'
                                value = [int]($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value
                            }
                            @{
                                id = 'Free'
                                label = 'Free CPU'
                                value = [int](100 - (($vm | Get-Stat -Stat cpu.usage.average -Realtime -maxsamples 1).value))
                            }
                                )  -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7  -CornerRadius 3 
                        
                        }


                    }
                }
            }
        }
    }
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -text "Hosts Utilization" -OnClick {
                                         Show-UDModal -Content {

                                         New-UDRow {
New-UDColumn -Size 12 -AutoRefresh -RefreshInterval 2 -Endpoint {
$null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
$ESXiHostsList = Get-VMHost * -Server LDNPINFVCA01
New-UDLayout -Columns 3 -Content {
Foreach($ESXiHost in $ESXiHostsList){
New-UDcard -Title ($ESXiHost.name) -TextAlignment center -size medium -Content {
New-UDColumn -Size 6 {
New-UDHeading -Text "Memory" 
New-UDNivoChart -Id 'MemoryChart' -Pie -DisableRadiusLabels -Colors @("#38bcb2","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used Memory'
value = [int]( $ESXiHost | select-object @{N='UsedMemory';E={$_.memoryusageGB / $_.memorytotalGB * 100 }}).usedmemory
}
@{
id = 'Free'
label = 'Free Memory'
value = [int]( $ESXiHost | select-object @{N='FreeMemory';E={100 - ($_.memoryusageGB / $_.memorytotalGB * 100)}}).freememory
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
New-UDColumn -Size 6 {
New-UDHeading -text "CPU" 
New-UDNivoChart -Id 'CPUChart' -Pie -DisableRadiusLabels -Colors @("#1F78B4","#CCCCCC") -Data @(
@{
id = 'Used'
label = 'Used CPU'
value = [int]( $ESXiHost | select-object @{N='UsedCPU';E={$_.CpuUsageMhz / $_.CpuTotalMhz * 100 }}).usedCPU
}
@{
id = 'Free'
label = 'Free CPU'
value = [int]( $ESXiHost | select-object @{N='FreeCPU';E={100 - ($_.CpuUsageMhz / $_.CpuTotalMhz * 100)}}).freeCPU
}
) -Height 200 -Width 300 -MarginBottom 50 -MarginTop 50 -MarginRight 110 -MarginLeft 60 -InnerRadius 0.5 -PadAngle 0.7 -CornerRadius 3 
}
}
}
}
}
}
                                         
                                              }
                                         
                                       
                                      }
                           New-UDButton -Text "Access Vcenter here" -OnClick { Invoke-UDRedirect -Url 'https://ldnpinfvcs02/' }
                           }
              
                           }
                           New-UDTab -Text 'LDNPINFVCS01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LDNPINFVCS01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCS01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LDNPINFVCS01| Select @{N="Vcenter";E={"LDNPINFVCS01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LDNPINFVCS01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server LDNPINFVCA02 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


                         Function Get-TriggeredAlarms {
  	                       param (
  		                    $vCenter = $(throw "A vCenter must be specified.")
  	                          )

                            
  		                       $vc =  $vCenter
  	                        

                            
  	                        $rootFolder = Get-Folder -Server $vc "Datacenters"

                            foreach ($ta in $rootFolder.ExtensionData.TriggeredAlarmState) {
  		                            $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  		                            $alarm.VC = $vCenter
  		                            $alarm.Alarm = (Get-View -Server $vc $ta.Alarm).Info.Name
  		                            $entity = Get-View -Server $vc $ta.Entity
  		                            $alarm.Entity = (Get-View -Server $vc $ta.Entity).Name
  		                            $alarm.EntityType = (Get-View -Server $vc $ta.Entity).GetType().Name
  		                            $alarm.Status = [string]$ta.OverallStatus
  		                            $alarm.Time = $ta.Time 
  		                            $alarm.Acknowledged = $ta.Acknowledged
  		                            $alarm.AckBy = $ta.AcknowledgedByUser
  		                            $alarm.AckTime = $ta.AcknowledgedTime
  		                            $alarm
  	                                 }
  	
                                    }

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms LDNPINFVCS01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'LDNPINFVCS02'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LDNPINFVCS02 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LDNPINFVCS02"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LDNPINFVCS02| Select @{N="Vcenter";E={"LDNPINFVCS02"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LDNPINFVCS02 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server LDNPINFVCA02 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


                         Function Get-TriggeredAlarms {
  	                       param (
  		                    $vCenter = $(throw "A vCenter must be specified.")
  	                          )

                            
  		                       $vc =  $vCenter
  	                        

                            
  	                        $rootFolder = Get-Folder -Server $vc "Datacenters"

                            foreach ($ta in $rootFolder.ExtensionData.TriggeredAlarmState) {
  		                            $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  		                            $alarm.VC = $vCenter
  		                            $alarm.Alarm = (Get-View -Server $vc $ta.Alarm).Info.Name
  		                            $entity = Get-View -Server $vc $ta.Entity
  		                            $alarm.Entity = (Get-View -Server $vc $ta.Entity).Name
  		                            $alarm.EntityType = (Get-View -Server $vc $ta.Entity).GetType().Name
  		                            $alarm.Status = [string]$ta.OverallStatus
  		                            $alarm.Time = $ta.Time 
  		                            $alarm.Acknowledged = $ta.Acknowledged
  		                            $alarm.AckBy = $ta.AcknowledgedByUser
  		                            $alarm.AckTime = $ta.AcknowledgedTime
  		                            $alarm
  	                                 }
  	
                                    }

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter LDNPINFVCS02

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'ARKPINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                                 
                                 function Check-ESXHost {

[cmdletbinding()] 

param (            
 [parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)]           
    [string[]]$ComputerName = $env:COMPUTERNAME        
)  

begin {


 $sess = New-PSSession -ComputerName ldnpinfadm05 -Credential $Cache:CorpCreds



} 
process { 


$scriptBlockStop = { 

                                                             Connect-VIServer -Server ARKPINFVCA01 -Username "corp\srvcDev42VC" -Password "R#2TwaM@"
     
                                                             Get-VMHost -Server ARKPINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"ARKPINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}}
                                                             }


Invoke-Command -Session $sess -ScriptBlock $scriptBlockStop




  }
end {
  Remove-PSSession -Session $sess
 }
}



                                Check-ESXHost | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate')
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server ARKPINFVCA01 | Select @{N="Vcenter";E={"ARKPINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server ARKPINFVCA01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 16

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server ARKPINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


                         Function Get-TriggeredAlarms {
  	                       param (
  		                    $vCenter = $(throw "A vCenter must be specified.")
  	                          )

                            
  		                       $vc =  $vCenter
  	                        

                            
  	                        $rootFolder = Get-Folder -Server $vc "Datacenters"

                            foreach ($ta in $rootFolder.ExtensionData.TriggeredAlarmState) {
  		                            $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  		                            $alarm.VC = $vCenter
  		                            $alarm.Alarm = (Get-View -Server $vc $ta.Alarm).Info.Name
  		                            $entity = Get-View -Server $vc $ta.Entity
  		                            $alarm.Entity = (Get-View -Server $vc $ta.Entity).Name
  		                            $alarm.EntityType = (Get-View -Server $vc $ta.Entity).GetType().Name
  		                            $alarm.Status = [string]$ta.OverallStatus
  		                            $alarm.Time = $ta.Time 
  		                            $alarm.Acknowledged = $ta.Acknowledged
  		                            $alarm.AckBy = $ta.AcknowledgedByUser
  		                            $alarm.AckTime = $ta.AcknowledgedTime
  		                            $alarm
  	                                 }
  	
                                    }

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter ARKPINFVCA01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           New-UDTab -Text 'LD5PINFVCA01'      -Content {
                           New-UDColumn -Size 3 {
                                 
                                New-UDTable  -Title "Host Not Connected Or Alarms Disabled" -Headers @('Vcenter','Name','ConnectionState','Powerstate')  -Endpoint {


                                 $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                 

                                 Start-Sleep 5
                                 
                                 Get-VMHost -Server LD5PINFVCA01 -State Disconnected, notresponding, maintenance,Disconnected | select  @{N="Vcenter";E={"LD5PINFVCA01"}},name, @{N="ConnectionState";E={[string]$_.ConnectionState}}, @{N="Powerstate";E={[string]$_.Powerstate}} | Out-UDTableData -Property @('Vcenter','Name','ConnectionState','Powerstate') 
                                 
                                 }
                                New-UDTable  -Title "Datastore Less Than 25% Free"  -Headers @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')  -Endpoint {


                                    $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 10
                                    
                                    Get-Datastore -Server LD5PINFVCA01 | Select @{N="Vcenter";E={"LD5PINFVCA01"}},@{N="DataStoreName";E={$_.Name}},@{N="Free Space(GB)";E={[math]::Round(($_.FreeSpaceGB))}},@{N="Percentage Free Space(%)";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}} | Where {$_."Percentage Free Space(%)" -le 25} | Out-UDTableData -Property @('Vcenter','DataStoreName','Free Space(GB)','Percentage Free Space(%)')
                                    

                                 
                                 }
                                    
                        
                           }
                           New-UDColumn -Size 3 {
                           New-UDTable  -Title "Host Status" -Headers @('VMHost','TriggeredAlarms','OverallStatus') -Endpoint {

                            $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret
                           
                            $VMHosts = Get-View -Server LD5PINFVCA01 -ViewType HostSystem -Property Name,OverallStatus,TriggeredAlarmstate
                            $FaultyVMHosts = $VMHosts | Where-Object {$_.TriggeredAlarmState -ne "{}"}

                             $progress = 1
                             $report = @()
                             if ($FaultyVMHosts -ne $null) {
                             foreach ($FaultyVMHost in $FaultyVMHosts) {
                             foreach ($TriggeredAlarm in $FaultyVMHost.TriggeredAlarmstate) {
            
                             $alarmID = $TriggeredAlarm.Alarm.ToString()
                             $object = New-Object PSObject
                             Add-Member -InputObject $object NoteProperty VMHost $FaultyVMHost.Name
                             Add-Member -InputObject $object NoteProperty TriggeredAlarms ("$(Get-AlarmDefinition -Id $alarmID)")
                             Add-Member -InputObject $object NoteProperty OverallStatus  ([string]$TriggeredAlarm.OverallStatus)
                             $report += $object
                               }
                              $progress++   
                             }
                            }


                           $report | Where-Object {$_.TriggeredAlarms -ne ""} | Out-UDTableData -Property @('VMHost','TriggeredAlarms','OverallStatus')
                           } 
                           New-UDTable  -Title "Hardware Status Warnings/Errors" -Headers @('Host','Name','Health')  -Endpoint{
                           
                                $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret

                                    Start-Sleep 16

                                foreach($esx in Get-VMHost){

                                $hs = Get-View -Server LD5PINFVCA01 -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem -ErrorAction SilentlyContinue

                                $hs.Runtime.SystemHealthInfo.NumericSensorInfo |

                                where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} |

                                Select @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}    | Out-UDTableData  -Property @('Host','Name','Health') 

}

                                     
                           }
                           
                           }
                           New-UDColumn -Size 6 {
                           New-UDGrid -PageSize 40 -Title "Alarms $Vcentername" -NoPaging -Headers @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Properties @('VC','EntityType','Alarm','Entity','Status','Time','Acknowledged') -Endpoint {
                           
                           $null = Connect-VIServer -Server $Cache:ViServerList -Session $Cache:ViServerList.SessionSecret


                         Function Get-TriggeredAlarms {
  	                       param (
  		                    $vCenter = $(throw "A vCenter must be specified.")
  	                          )

                            
  		                       $vc =  $vCenter
  	                        

                            
  	                        $rootFolder = Get-Folder -Server $vc "Datacenters"

                            foreach ($ta in $rootFolder.ExtensionData.TriggeredAlarmState) {
  		                            $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  		                            $alarm.VC = $vCenter
  		                            $alarm.Alarm = (Get-View -Server $vc $ta.Alarm).Info.Name
  		                            $entity = Get-View -Server $vc $ta.Entity
  		                            $alarm.Entity = (Get-View -Server $vc $ta.Entity).Name
  		                            $alarm.EntityType = (Get-View -Server $vc $ta.Entity).GetType().Name
  		                            $alarm.Status = [string]$ta.OverallStatus
  		                            $alarm.Time = $ta.Time 
  		                            $alarm.Acknowledged = $ta.Acknowledged
  		                            $alarm.AckBy = $ta.AcknowledgedByUser
  		                            $alarm.AckTime = $ta.AcknowledgedTime
  		                            $alarm
  	                                 }
  	
                                    }

                           

                             $alarms = @()
                             foreach ($vCenter in $vCenters) {
  	                         Write-Host "Getting alarms from $vCenter."
  	                         $alarms += Get-TriggeredAlarms $vCenter
                               }

                             $alarms | Out-GridView -Title "Triggered Alarms"

                             $vcenteralarm = Get-TriggeredAlarms -vCenter LD5PINFVCA01

                             Start-Sleep 20
                                           $vcenteralarm | Out-UDGridData
                                  

                              }

                           }
              
                           }
                           
                           

                           }
                    }


                            
               }

}
$pages += New-UDPage -Name "VMs" -Content {
  
   New-UDTable -Title "Check List" -Headers @("Application","Frequency","Region","Link","Status")  -Endpoint {

            $Cache:Table = $Cache:Link  |%    { 
                    [PSCustomObject]@{
                        Application = $_.application
                        Frequency = $_.Frequency
                        Region = $_.region
                        link = $_.link
                        Status = New-UDSelect  -Option {
                           
                                New-UDSelectOption -Name "OK" -Value 1 
                                New-UDSelectOption -Name "Failed" -Value 2 
                                New-UDSelectOption -Name 'Some Failure' -Value 3 
                            
                        } 
                        
                    }
                } 

              $Cache:table  | Out-UDTableData -Property  @("Application","Frequency","Region","Link","Status")    

            }
   New-UDButton -Text "Send Result" -OnClick {
   
  $Cache:table |% { 
                    [PSCustomObject]@{
                        Application = $_.application
                        Frequency = $_.Frequency
                        Region = $_.region
                        link = $_.link
                        Status = $_.Status
                        
                    }
                } | Export-Csv -Path C:\test.csv -NoTypeInformation
   
   }     
            




} 









 


$ei = New-UDEndpointInitialization -Module @("C:\Program Files\WindowsPowerShell\Modules\VMware.VimAutomation.Core\10.1.0.8344055\VMware.VimAutomation.Core.psm1")
$Dashboard = New-UDDashboard  -Title 'Exchange Morning Check'  -FontColor white -NavBarFontColor white -Page $pages  -EndpointInitialization $ei 
Start-UDDashboard -Port 10003 -Dashboard $Dashboard -Endpoint @($DCdiagEndpoint,$Schedule) -AdminMode

