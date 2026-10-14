$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    python -m venv .venv
}
& '.venv\Scripts\python.exe' -m pip install -e . 'pyinstaller>=6.22,<7'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& '.\build.ps1'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Emumee is ready. Try: .\emumee.ps1 persona'
