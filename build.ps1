param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

if (-not $SkipBuild) {
    & (Join-Path $projectRoot 'tools/build_rust.ps1') -Release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$dist = Join-Path $projectRoot 'dist'
New-Item -ItemType Directory -Path $dist -Force | Out-Null
$bundleName = 'Emumee-rust-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$destination = Join-Path 'dist' $bundleName
& (Join-Path $projectRoot 'tools/package_rust.ps1') -Destination $destination
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$pointer = Join-Path $dist 'current-rust-bundle.txt'
$temporary = Join-Path $dist ('.current-' + [Guid]::NewGuid().ToString('N') + '.tmp')
[System.IO.File]::WriteAllText($temporary, $bundleName + "`n", [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::Move($temporary, $pointer, $true)
Write-Host "Rust Emumee bundle built in $destination."
