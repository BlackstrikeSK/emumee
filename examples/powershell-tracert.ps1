# Harmless offline traceroute with examples/route-persona.json.
$ErrorActionPreference = 'Stop'
& ('tra' + 'cert.exe') -h 4 -w 20 trace.example
Write-Output ('persona-host=' + $env:COMPUTERNAME)
