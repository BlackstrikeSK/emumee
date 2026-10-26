$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $projectRoot 'dist'
$pointer = Join-Path $dist 'current-rust-bundle.txt'
if (-not (Test-Path -LiteralPath $pointer -PathType Leaf)) {
    throw 'No Rust bundle is selected. Run .\setup.ps1 or .\build.ps1 first.'
}
$bundleName = [System.IO.File]::ReadAllText($pointer).Trim()
if ($bundleName -cnotmatch '^Emumee-rust-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$') {
    throw 'Invalid Rust bundle pointer.'
}
$bundle = Join-Path $dist $bundleName
$executable = Join-Path $bundle 'emumee-rs.exe'
$receiptPath = Join-Path $bundle 'rust-worker-build.json'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf) -or
    -not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    throw 'Selected Rust bundle is incomplete. Run .\build.ps1.'
}
$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
$hash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
if ($receipt.controller_sha256 -ne $hash) {
    throw 'Selected Rust controller differs from its bundle receipt.'
}
& $executable @args
exit $LASTEXITCODE
