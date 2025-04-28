$secgroups = Get-Content -Path 'D:\bulk\finance audit\corpgroup.txt'





$final = foreach ($sec in $secgroups){do{

Get-ADGroup  "$sec" | Select name

}while ($false)
}

$final