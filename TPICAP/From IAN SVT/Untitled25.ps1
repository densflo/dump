

$scriptBlock = {


 cmd.exe /c "c:\program files\timekeeper\release64\tkstatus.bat"



}

Invoke-Command -ComputerName LDN2WS068N02 -ScriptBlock $scriptBlock