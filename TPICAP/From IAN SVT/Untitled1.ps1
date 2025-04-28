$FilePath = "\\ad.tullib.com\corp\GLOBAL\emea" 


(Get-Acl -path $FilePath).Access | Select  @{N="FileSystemRights";E={[string]$_.FileSystemRights}},@{N="IdentityReference";E={[string ]$_.IdentityReference}},@{N="AccessControlType";E={[string]$_.AccessControlType}},@{Name="Owner";Expression={[string](Get-Acl -path $FilePath).owner}}