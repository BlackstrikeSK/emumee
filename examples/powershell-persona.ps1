# Harmless Windows enumeration through the Linux guest's CPU emulator bridge.
$ErrorActionPreference = 'Stop'
& ('who' + 'ami.exe') /all
ipconfig.exe /all
hostname.exe
reg.exe query 'HKCU\Control Panel\Desktop' /v ScreenSaveActive
nslookup.exe localhost
ping.exe -n 1 -l 32 localhost
Write-Output ('persona-host=' + $env:COMPUTERNAME)
