param([string]$Distribution = 'Ubuntu')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$outputDirectory = Join-Path $repoRoot 'output\powershell-guest-tools'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$sourcePath = Join-Path $PSScriptRoot 'powershell_guest_tool_shim.c'
$outputPath = Join-Path $outputDirectory 'shim'
$linuxSource = (& wsl.exe -d $Distribution --exec wslpath -u $sourcePath).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve observer source in WSL' }
$linuxOutput = (& wsl.exe -d $Distribution --exec wslpath -u $outputPath).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve observer output in WSL' }
& wsl.exe -d $Distribution --exec gcc -static -O2 -Wall -Wextra -Werror $linuxSource -o $linuxOutput
if ($LASTEXITCODE -ne 0) { throw 'Guest shim build requires Linux x86-64 GCC and libc development files' }
Write-Output $outputPath
