$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$executable = Join-Path $projectRoot '.venv\Scripts\emumee.exe'
if (-not (Test-Path -LiteralPath $executable)) {
    Write-Error 'Run .\setup.ps1 first.'
    exit 1
}
& $executable @args
exit $LASTEXITCODE
