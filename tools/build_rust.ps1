param([switch]$Release,[switch]$Test,[switch]$Lint,[switch]$Validation,[string]$Package,[string]$TestFilter)
$ErrorActionPreference='Stop'
if ($Test -and $Lint) {throw 'Choose either -Test or -Lint.'}
if ($TestFilter -and -not $Test) {throw 'TestFilter requires -Test.'}
if ($Validation -and (-not $Test -or $Release)) {throw 'Validation is a source-test profile; use -Validation -Test without -Release.'}
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$env:CMAKE_TOOLCHAIN_FILE=Join-Path (Get-Location) 'rust\cmake\windows-toolchain.cmake'
$localClang=Join-Path (Get-Location) 'output\rust-toolchain\libclang\clang\native'
$localNinja=Join-Path (Get-Location) 'output\rust-toolchain\ninja\bin'
if (-not $env:LIBCLANG_PATH -and (Test-Path -LiteralPath (Join-Path $localClang 'libclang.dll'))) {
    $env:LIBCLANG_PATH=$localClang
}
if (Test-Path -LiteralPath (Join-Path $localNinja 'ninja.exe')) {$env:PATH=$localNinja+';'+$env:PATH}
if (-not $env:BINDGEN_EXTRA_CLANG_ARGS) {
    $vcRoot=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC'
    if (Test-Path -LiteralPath $vcRoot) {
        $vc=Get-ChildItem -LiteralPath $vcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        $sdkRoot=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
        $sdk=Get-ChildItem -LiteralPath $sdkRoot -Directory -Filter '10.*' | Sort-Object Name -Descending | Select-Object -First 1
        $includes=@((Join-Path $vc.FullName 'include'))
        if ($sdk) {$includes+=@('ucrt','shared','um') | ForEach-Object {Join-Path $sdk.FullName $_}}
        $env:BINDGEN_EXTRA_CLANG_ARGS=($includes | ForEach-Object {'-isystem "'+$_+'"'}) -join ' '
    }
}
$arguments=@($(if ($Test) {'test'} elseif($Lint) {'clippy'} else {'build'}),'--locked')
if ($Package) {$arguments+=@('--package',$Package)} else {$arguments+='--workspace'}
if ($Validation) {$arguments+=@('--profile','validation','--jobs','2')} elseif ($Release) {$arguments+='--release'}
if ($TestFilter) {$arguments+=$TestFilter}
if ($Test) {$arguments+='--no-run'}
if ($Lint) {$arguments+=@('--all-targets','--','-D','warnings')}
& cargo @arguments
if ($LASTEXITCODE -ne 0) {exit $LASTEXITCODE}
if ($Lint) {exit 0}
$profile=if ($Validation) {'validation'} elseif ($Release) {'release'} else {'debug'}
$targetRoot=Join-Path (Get-Location) ('target\'+$profile)
$native=Get-ChildItem -LiteralPath (Join-Path $targetRoot 'build') -Recurse -File -Filter 'unicorn.dll' |
    Where-Object {$_.FullName -like '*\out\bin\unicorn.dll'} | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if (-not $native) {throw 'The native Unicorn DLL was not installed by the build.'}
Copy-Item -LiteralPath $native.FullName -Destination (Join-Path $targetRoot 'unicorn.dll')
if (Test-Path -LiteralPath (Join-Path $targetRoot 'deps')) {
    Copy-Item -LiteralPath $native.FullName -Destination (Join-Path $targetRoot 'deps\unicorn.dll')
}
if ($Test) {
    $arguments=@($arguments | Where-Object {$_ -ne '--no-run'})
    & cargo @arguments
}
exit $LASTEXITCODE
