cd C:\Windows\System32\inetsrv

.\appcmd.exe stop site /site.name:svt

start-sleep -Seconds 4
.\appcmd.exe recycle apppool /apppool.name:DefaultAppPool
.\appcmd.exe recycle apppool /apppool.name:".NET v4.5 Classic"
.\appcmd.exe recycle apppool /apppool.name:".NET v4.5"


start-sleep -Seconds 4

.\appcmd.exe start site /site.name:svt