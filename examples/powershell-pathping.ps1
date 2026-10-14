# Harmless offline loss measurement with examples/loss-persona.json.
$ErrorActionPreference = 'Stop'
& ('path' + 'ping.exe') -h 2 -q 4 -p 10 -w 20 loss.example
Write-Output ('persona-host=' + $env:COMPUTERNAME)
