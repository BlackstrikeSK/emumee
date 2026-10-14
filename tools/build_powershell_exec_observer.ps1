param([string]$Distribution = 'Ubuntu')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$outputDirectory = Join-Path $repoRoot 'output\powershell-exec-observer'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$sourcePath = Join-Path $PSScriptRoot 'powershell_exec_observer.c'
$outputPath = Join-Path $outputDirectory 'observer'
$linuxSource = (& wsl.exe -d $Distribution --exec wslpath -u $sourcePath).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve observer source in WSL' }
$linuxOutput = (& wsl.exe -d $Distribution --exec wslpath -u $outputPath).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve observer output in WSL' }
& wsl.exe -d $Distribution --exec gcc -static -O2 -Wall -Wextra -Werror $linuxSource -o $linuxOutput -lcrypto -ldl -pthread
if ($LASTEXITCODE -ne 0) { throw 'Observer build requires Linux x86-64 GCC, libc development files, and libssl-dev' }
Write-Output $outputPath
