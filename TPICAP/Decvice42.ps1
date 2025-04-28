
Set-Service -Name Winmgmt -StartupType Disabled
Stop-Service -Name Winmgmt -Force -NoWait -WarningAction Ignore
Start-Sleep -s 10

Winmgmt /salvagerepository %windir%\System32\wbem
Winmgmt /resetrepository %windir%\System32\wbem

Set-Service -Name Winmgmt -StartupType Automatic
Start-Service -Name Winmgmt -WarningAction Ignore




switch -Wildcard ($env:COMPUTERNAME) {
    "BLX*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "SYD*" {
        $AccountName = "APACLD42Srv"
   
    }
    "TOK*" {
        $AccountName = "APACLD42Srv"
   
    }
     "TK*" {
     $AccountName = "APACLD42Srv"
      
    }
    "BKK*" {
        $AccountName = "APACLD42Srv"
   
    }
    "HK*" {
        $AccountName = "APACLD42Srv"
   
    }
    "SIN*" {
        $AccountName = "APACLD42Srv"
   
    }
    "SLT*" {
        $AccountName = "APACLD42Srv"
   
    }
    "SNG*" {
        $AccountName = "APACLD42Srv"
   
    }
    "SHG*" {
        $AccountName = "APACLD42Srv"
   
    }
    "SEO*" {
        $AccountName = "APACLD42Srv"
   
    }
    "MLA*" {
        $AccountName = "APACLD42Srv"
   
    }
    "PH*" {
        $AccountName = "APACLD42Srv"
   
    }
    "NJ*" {
        $AccountName = "AMERLD42Srv"
       
    }
    "NY*" {
        $AccountName = "AMERLD42Srv"
       
    }
    "LOU*" {
        $AccountName = "AMERLD42Srv"
       
            }
    "CHI*" {
        $AccountName = "AMERLD42Srv"
       
    }
    "DUR*" {
        $AccountName = "AMERLD42Srv"
       
    }
    "TOR*" {
        $AccountName = "AMERLD42Srv"
       
    }
    "NOR*" {
        $AccountName = "AMERLD42Srv"
       
    }
    "HOU*" {
        $AccountName = "AMERLD42Srv"
       
    }
    "BIS*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "BFS*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "JHB*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "AMS*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "DUB*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "GEN*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "ZUR*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "ALC*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "BER*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "MAD*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "COP*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "FFT*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "PAR*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "BAH*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "LD5*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "LDN*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "EUW*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "WEL*" {
        $AccountName = "EMEALD42Srv"
      
    }
    "USE*" {
        $AccountName = "AMERLD42Srv"
      
    }
    "ASE*" {
        $AccountName = "APACLD42Srv"
      
    }
    "SG*" {
        $AccountName = "APACLD42Srv"
      
    }
     "JP*" {
     $AccountName = "APACLD42Srv"
      
    }
     "ALC*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "AMS*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "AU*" {
     $AccountName = "APACLD42Srv"
      
    }
     "BER*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "BR*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "DE*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "JP*" {
     $AccountName = "APACLD42Srv"
      
    }
     "EBD*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "GB*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "PVM*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "TBD*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "US*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "CHI*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "KOR*" {
     $AccountName = "APACLD42Srv"
      
    }
     "NA*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "TOR*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "UK*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "ABS*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "ASE*" {
     $AccountName = "APACLD42Srv"
      
    }
     "BOC*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "EC2*" {
     $AccountName = "EMEALD42Srv"
      
    }
     "HMO*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "HOU*" {
     $AccountName = "AMERLD42Srv"
      
    }
     "INF*" {
     $AccountName = "EMEALD42Srv"
      
    }
}

Function Set-WmiNamespaceSecurity {

    # Copyright (c) Microsoft Corporation.  All rights reserved. 
    # For personal use only.  Provided AS IS and WITH ALL FAULTS.
 
    # Set-WmiNamespaceSecurity.ps1
    # Example: Set-WmiNamespaceSecurity root/cimv2 add steve Enable,RemoteAccess
 
    Param ( [parameter(Mandatory=$true,Position=0)][string] $namespace,
        [parameter(Mandatory=$true,Position=1)][string] $operation,
        [parameter(Mandatory=$true,Position=2)][string] $account,
        [parameter(Position=3)][string[]] $permissions = $null,
        [bool] $allowInherit = $true,
        [bool] $deny = $false,
        [string] $computerName = ".",
        [System.Management.Automation.PSCredential] $credential = $null)
   
    Process {
        $ErrorActionPreference = "Stop"
 
        Function Get-AccessMaskFromPermission($permissions) {
            $WBEM_ENABLE            = 1
                    $WBEM_METHOD_EXECUTE = 2
                    $WBEM_FULL_WRITE_REP   = 4
                    $WBEM_PARTIAL_WRITE_REP              = 8
                    $WBEM_WRITE_PROVIDER   = 0x10
                    $WBEM_REMOTE_ACCESS    = 0x20
                    $WBEM_RIGHT_SUBSCRIBE = 0x40
                    $WBEM_RIGHT_PUBLISH      = 0x80
            $READ_CONTROL = 0x20000
            $WRITE_DAC = 0x40000
       
            $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE,$WBEM_METHOD_EXECUTE,$WBEM_FULL_WRITE_REP,`
                $WBEM_PARTIAL_WRITE_REP,$WBEM_WRITE_PROVIDER,$WBEM_REMOTE_ACCESS,`
                $READ_CONTROL,$WRITE_DAC
            $WBEM_RIGHTS_STRINGS = "Enable","MethodExecute","FullWrite","PartialWrite",`
                "ProviderWrite","RemoteAccess","ReadSecurity","WriteSecurity"
 
            $permissionTable = @{}
 
            for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
                $permissionTable.Add($WBEM_RIGHTS_STRINGS[$i].ToLower(), $WBEM_RIGHTS_FLAGS[$i])
            }
       
            $accessMask = 0
 
            foreach ($permission in $permissions) {
                if (-not $permissionTable.ContainsKey($permission.ToLower())) {
                    throw "Unknown permission: $permission`nValid permissions: $($permissionTable.Keys)"
                }
                $accessMask += $permissionTable[$permission.ToLower()]
            }
       
            $accessMask
        }
 
        if ($PSBoundParameters.ContainsKey("Credential")) {
            $remoteparams = @{ComputerName=$computer;Credential=$credential}
        } else {
            $remoteparams = @{ComputerName=$computerName}
        }
       
        $invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@"} + $remoteParams
 
        $output = Invoke-WmiMethod @invokeparams -Name GetSecurityDescriptor
        if ($output.ReturnValue -ne 0) {
         throw "GetSecurityDescriptor failed: $($output.ReturnValue)"
        }
 
        $acl = $output.Descriptor
        $OBJECT_INHERIT_ACE_FLAG = 0x1
        $CONTAINER_INHERIT_ACE_FLAG = 0x2
 
        $computerName = (Get-WmiObject @remoteparams Win32_ComputerSystem).Name
   
        if ($account.Contains('\')) {
            $domainaccount = $account.Split('\')
            $domain = $domainaccount[0]
            if (($domain -eq ".") -or ($domain -eq "BUILTIN")) {
                $domain = $computerName
            }
            $accountname = $domainaccount[1]
        } elseif ($account.Contains('@')) {
            $domainaccount = $account.Split('@')
            $domain = $domainaccount[1].Split('.')[0]
            $accountname = $domainaccount[0]
        } else {
            $domain = $computerName
            $accountname = $account
        }
 
        $getparams = @{Class="Win32_Account";Filter="Domain='$domain' and Name='$accountname'"}
 
        $win32account = Get-WmiObject @getparams
 
        if ($win32account -eq $null) {
            throw "Account was not found: $account"
        }
 
        switch ($operation) {
            "add" {
                if ($permissions -eq $null) {
                    throw "-Permissions must be specified for an add operation"
                }
                $accessMask = Get-AccessMaskFromPermission($permissions)
   
                $ace = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
                $ace.AccessMask = $accessMask
                if ($allowInherit) {
                    $ace.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
                } else {
                    $ace.AceFlags = 0
                }
                       
                $trustee = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
                $trustee.SidString = $win32account.Sid
                $ace.Trustee = $trustee
           
                $ACCESS_ALLOWED_ACE_TYPE = 0x0
                $ACCESS_DENIED_ACE_TYPE = 0x1
 
                if ($deny) {
                    $ace.AceType = $ACCESS_DENIED_ACE_TYPE
                } else {
                    $ace.AceType = $ACCESS_ALLOWED_ACE_TYPE
                }
 
                $acl.DACL += $ace.psobject.immediateBaseObject
            }
       
            "delete" {
                if ($permissions -ne $null) {
                    throw "Permissions cannot be specified for a delete operation"
                }
       
                [System.Management.ManagementBaseObject[]]$newDACL = @()
                foreach ($ace in $acl.DACL) {
                    if ($ace.Trustee.SidString -ne $win32account.Sid) {
                        $newDACL += $ace.psobject.immediateBaseObject
                    }
                }
 
                $acl.DACL = $newDACL.psobject.immediateBaseObject
            }
       
            default {
                throw "Unknown operation: $operation`nAllowed operations: add delete"
            }
        }
 
        $setparams = @{Name="SetSecurityDescriptor";ArgumentList=$acl.psobject.immediateBaseObject} + $invokeParams
 
        $output = Invoke-WmiMethod @setparams
        if ($output.ReturnValue -ne 0) {
            throw "SetSecurityDescriptor failed: $($output.ReturnValue)"
        }
    }
}


# $password1 = ConvertTo-SecureString -String 'DGHazdfjeyf388*c09(446g-dgjbverr!' -AsPlainText -Force
# $password2 = ConvertTo-SecureString -String '5bNa13CeChWOsg%Tu367@XlJI9jn7UUW' -AsPlainText -Force
# $password3 = ConvertTo-SecureString -String 'bn-mbh_jHRTDS$^KKB]6gdrryu$)(222' -AsPlainText -Force

# Remove local D42 account'

if($AccountName -eq "EMEALD42Srv"){net user $AccountName /delete}else{}
if($AccountName -eq "APACLD42Srv"){net user $AccountName /delete}else{}
if($AccountName -eq "AMERLD42Srv"){net user $AccountName /delete}else{}

# Set-LocalAccountForDevice42

# Remove local accout from Local Admins and add to 'Performance Monitor Users' and 'Distributed COM Users'

        if($AccountName -eq "EMEALD42Srv"){net user $AccountName 'DGHazdfjeyf388*c09(446g-dgjbverr!' /y /ADD /expires:never}else{}
        if($AccountName -eq "APACLD42Srv"){net user $AccountName '5bNa13CeChWOsg%Tu367@XlJI9jn7UUW' /y /ADD /expires:never}else{}
        if($AccountName -eq "AMERLD42Srv"){net user $AccountName 'bn-mbh_jHRTDS$^KKB]6gdrryu$)(222' /y /ADD /expires:never}else{} 
       
       
 # net user $AccountName "DGHazdfjeyf388*c09(446g-dgjbverr!" /active:yes
 net localgroup 'Performance Monitor Users' $AccountName /add
 net localgroup 'Distributed COM Users'  $AccountName /add
 wmic useraccount WHERE "Name='$AccountName'" set PasswordExpires=false   

 
 

# Configure RPC and WMI services, set to Automatic and Enabled

  Set-Service -Name WinMgmt -StartupType Automatic

# Configure Firewall rules for 'Windows Management Instrumentation (DCOM-In)' and 'Windows Management Instrumentation (WMI-In)'

  Enable-NetFirewallRule -DisplayName 'Windows Management Instrumentation (WMI-In)'
  Enable-NetFirewallRule -DisplayName 'Windows Management Instrumentation (DCOM-In)' 
  

# Permission WMI with Enable Account, Remot Enable and Read Security



  Set-WmiNamespaceSecurity -namespace root/cimv2 -operation add -account $AccountName -permissions Enable,RemoteAccess,ReadSecurity -allowInherit:$true
  Set-WmiNamespaceSecurity -namespace root/WMI -operation add -account $AccountName -permissions Enable,RemoteAccess,ReadSecurity -allowInherit:$true
  Set-WmiNamespaceSecurity -namespace root/Default -operation add -account $AccountName -permissions Enable,RemoteAccess,ReadSecurity -allowInherit:$true