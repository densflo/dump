function Enable-PSRemoting {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )

    # Test WSMan connectivity
    Write-Host "Testing WSMan connectivity to $ComputerName"
    $wsman = Test-WSMan -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
    if ($null -eq $wsman) {
        Write-Host "WSMan test failed for $ComputerName. Enabling WSMan and PowerShell remoting using PsExec."

        # Enable WSMan and PowerShell remoting using PsExec
        $psexecOutput = & psexec \\$ComputerName -s -u $Credential.UserName -p ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password))) cmd /c "winrm quickconfig -q && winrm set winrm/config/winrs '@{MaxMemoryPerShellMB=`"1024`"}' && winrm set winrm/config '@{MaxTimeoutms=`"1800000`"}' && netsh advfirewall firewall set rule group=`"Windows Remote Management`" new enable=yes"
        Write-Host "PsExec output for $ComputerName':' $psexecOutput"

        # Test WSMan and PowerShell remoting again
        $wsman = Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue
        if ($null -eq $wsman) {
            Write-Host "WSMan test failed for $ComputerName even after enabling WSMan and PowerShell remoting using PsExec. Exiting."
            exit
        }
    }

    # Test PowerShell remoting
    Write-Host "Testing PowerShell remoting to $ComputerName"
    $psremoting = Test-WSMan -ComputerName $ComputerName -Authentication Negotiate -Credential $Credential -ErrorAction SilentlyContinue
    if ($null -eq $psremoting) {
        Write-Host "PowerShell remoting test failed for $ComputerName. Enabling WSMan and PowerShell remoting using PsExec."

        # Enable WSMan and PowerShell remoting using PsExec
        $psexecOutput = & psexec \\$ComputerName -s -u $Credential.UserName -p ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password))) cmd /c "winrm quickconfig -q && winrm set winrm/config/winrs '@{MaxMemoryPerShellMB=`"1024`"}' && winrm set winrm/config '@{MaxTimeoutms=`"1800000`"}' && netsh advfirewall firewall set rule group=`"Windows Remote Management`" new enable=yes"
        Write-Host "PsExec output for $ComputerName':' $psexecOutput"

        # Test PowerShell remoting again
        $psremoting = Test-WSMan -ComputerName $ComputerName -Authentication Negotiate -Credential $Credential -ErrorAction SilentlyContinue
        if ($null -eq $psremoting) {
            Write-Host "PowerShell remoting test failed for $ComputerName even after enabling WSMan and PowerShell remoting using PsExec. Exiting."
            exit
        }
    }

    Write-Host "PowerShell remoting is enabled on $ComputerName"
}
