[CmdletBinding(DefaultParameterSetName='Package')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Package')][string]$Destination,
    [Parameter(Mandatory=$true,ParameterSetName='Fingerprint')][switch]$SourceFingerprintOnly
)
$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $workspace
if ($PSCmdlet.ParameterSetName -eq 'Package') {
    $target=if ([IO.Path]::IsPathRooted($Destination)) {[IO.Path]::GetFullPath($Destination)} else {[IO.Path]::GetFullPath((Join-Path $workspace $Destination))}
    if (Test-Path -LiteralPath $target) {throw 'Preserve the existing frozen Rust bundle; choose a new destination.'}
}
$selected=@('Cargo.toml','Cargo.lock','tools/build_rust.ps1','tools/package_rust.ps1','tools/package_rust_linux.sh')
$selected+=Get-ChildItem -LiteralPath rust -Recurse -File | Where-Object {$_.Extension -in @('.rs','.toml','.cmake','.json')} | ForEach-Object {$_.FullName.Substring($workspace.Length+1).Replace('\','/')}
$sources=[ordered]@{}
$selected=[string[]]@($selected | Select-Object -Unique)
[Array]::Sort($selected,[StringComparer]::Ordinal)
$sourceText=[System.Text.StringBuilder]::new()
foreach ($relative in $selected) {
    $sources[$relative]=(Get-FileHash -LiteralPath (Join-Path $workspace $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
    [void]$sourceText.Append($relative).Append([char]0).Append($sources[$relative]).Append("`n")
}
$sourceBytes=[System.Text.Encoding]::UTF8.GetBytes($sourceText.ToString())
$hasher=[System.Security.Cryptography.SHA256]::Create()
try {$sourceDigest=[BitConverter]::ToString($hasher.ComputeHash($sourceBytes)).Replace('-','').ToLowerInvariant()}
finally {$hasher.Dispose()}
if ($PSCmdlet.ParameterSetName -eq 'Fingerprint') {
    [ordered]@{source_tree_sha256=$sourceDigest;source_files=$sources} | ConvertTo-Json -Depth 5
    exit 0
}
$compiled=& (Join-Path $workspace 'target\release\emumee-rs.exe') build-info
if ($LASTEXITCODE -ne 0) {throw 'Rust binary has no valid build fingerprint; complete the build first.'}
$compiled=$compiled | ConvertFrom-Json
if ($compiled.source_tree_sha256 -ne $sourceDigest) {throw 'Rust executable is stale relative to current source; complete the build before packaging.'}
$workerBuild=& (Join-Path $workspace 'target\release\emumee-worker.exe') --build-info | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $workerBuild.source_tree_sha256 -ne $sourceDigest) {throw 'Rust worker executable is stale relative to current source.'}
$null=New-Item -ItemType Directory -Path $target
foreach ($file in @('emumee-rs.exe','emumee-worker.exe','unicorn.dll')) {
    Copy-Item -LiteralPath (Join-Path $workspace ('target\release\'+$file)) -Destination (Join-Path $target $file)
}
$copied=& (Join-Path $target 'emumee-rs.exe') build-info | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $copied.source_tree_sha256 -ne $sourceDigest) {throw 'Packaged Rust build fingerprint changed during copying.'}
$receipt=[ordered]@{
    schema=2;backend='rust/unicorn-x86';backends=@('rust/unicorn-x86','rust/managed-il');unicorn_version='2.1.5';
    controller_sha256=(Get-FileHash -LiteralPath (Join-Path $target 'emumee-rs.exe') -Algorithm SHA256).Hash.ToLowerInvariant();
    worker_sha256=(Get-FileHash -LiteralPath (Join-Path $target 'emumee-worker.exe') -Algorithm SHA256).Hash.ToLowerInvariant();
    unicorn_sha256=(Get-FileHash -LiteralPath (Join-Path $target 'unicorn.dll') -Algorithm SHA256).Hash.ToLowerInvariant();
    source_tree_sha256=$sourceDigest;source_files=$sources;scope='Rust migration development bundle with contained submitted-driver diagnostics and bounded Linux ELF guest profiles. This receipt alone certifies neither general Windows or Linux compatibility nor artifact recovery.'
}
[IO.File]::WriteAllText((Join-Path $target 'rust-worker-build.json'),($receipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
Write-Output "Frozen Rust development bundle: $target"
