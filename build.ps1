$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    Write-Error 'Run .\setup.ps1 first.'
    exit 1
}
& $python -m PyInstaller --noconfirm --clean 'Emumee.spec'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $python 'tools\patch_bootloader_cfg.py' 'dist\Emumee\Emumee.exe'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& 'dist\Emumee\Emumee.exe' persona | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Isolated Emumee bundle built in dist\Emumee.'
