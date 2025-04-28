#user SAM Account Name
$usertest = "a_patriciaanne"
$newdestination = "\\ad.tullib.com\CORP\GLOBAL\APAC\SG\UserDir15$"

#getting exisisting Home Drive of the user
Write-Host "getting current user Home folder" -ForegroundColor Green
$userhomedrive = Get-ADUser -Identity $usertest -Properties * | select HomeDirectory
$Currentdirectory = $userhomedrive.HomeDirectory
$Currentdirectory

#will Create User Folder in the destination File Server
Write-Host "Creating Folder in the destination fileshare $newdestination\$usertest" -ForegroundColor Green
New-Item  -Path "$newdestination\$usertest" -ItemType directory

#will Do the copy of the filder to the new File server with sercurity permissions
Write-Host "start of robocopy" -ForegroundColor Green
robocopy $Currentdirectory "$newdestination\$usertest" /E /J /COPYALL /MT:1 /IS /IT /IM /X /V /NP /mir /sec
Write-host "done moving files"

#will update the home drive on the user object with the new one
Write-host "updating user home drive $newdestination\$usertest" -ForegroundColor Green
Set-ADUser -Identity $usertest -HomeDirectory "$newdestination\$usertest"

write-host "working $usertest permission"
$acl = Get-Acl "\\ad.tullib.com\corp\GLOBAL\EMEA\PAR2\UserDir$\$usertest" 
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$usertest","Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl "$newdestination\$usertest" 