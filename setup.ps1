$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'Install Rust 1.85 or newer and make cargo available before running setup.ps1.'
}
& (Join-Path $projectRoot 'build.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Emumee is ready. Try: .\emumee.ps1 persona'
