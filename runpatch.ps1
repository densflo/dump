function Run-PatchScan {
    param(
        [string]$machinegroupname
    )

    $scanTemplate = "Current"
    $AccountName = "corp\srvcPMSServer"
    $Password = Get-ChildItem Env:srvcPMSServer | Select-Object -ExpandProperty Value
    $accontPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AccountName,$accontPassword

    $ShavlikConsole = $machinegroupname.Split('\')[0]

    Start-Job -Name $MachineGName -ScriptBlock {
        PARAM($MachineGName,$ShavlikConsole,$scanTemplate,$Creds)

        D:\IvantiRestAPI\Shavlik-Scan-Patch.ps1 -MachineGroupName $MachineGName -ConsoleName $ShavlikConsole -ScanTemplateName "$scanTemplate"  -Credential $Creds
    } -ArgumentList $machinegroupname,$ShavlikConsole,$scanTemplate,$Creds
}

# Example usage:
# Run-PatchScan -machinegroupname "ldn1ws7002\EMEAPatch1-LDN-c1-p1-sat-00"
