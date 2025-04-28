$patches = Get-Content -Path C:\temp\appd.txt

foreach($patch in $patches){

Copy-Item -Path "\\ldn1ws7001\D$\Patches\$patch"  -Destination "C:\temp" 

}

$dir = (Get-Item -Path "C:\temp" -Verbose).FullName
 Foreach($item in (ls $dir *.msu -Name))
 {
	echo $item
	$item = $dir + "\" + $item
	wusa $item /quiet /norestart | Out-Null
 }