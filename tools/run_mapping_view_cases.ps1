param(
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repo = Split-Path -Parent $PSScriptRoot
$runner = Join-Path $repo 'dist\Emumee\Emumee.exe'
$python = Join-Path $repo '.venv\Scripts\python.exe'
$verifier = Join-Path $PSScriptRoot 'verify_mapping_view_owner.py'
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Build the packaged worker first: $runner"
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Set up the Python environment first: $python"
}
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repo ('output\mapping-view-check-' + [guid]::NewGuid().ToString('N'))
} elseif (-not [System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot = Join-Path $repo $OutputRoot
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) {
    throw "Choose a new output directory: $OutputRoot"
}
New-Item -ItemType Directory -Path $OutputRoot | Out-Null

foreach ($arch in @('x86', 'x64')) {
    $cases = @(
        "child_parent_mapping_view_read_$arch",
        "child_parent_mapping_view_write_$arch",
        "child_parent_pagefile_view_read_$arch",
        "child_parent_pagefile_view_execute_$arch",
        "child_parent_pagefile_view_api_read_$arch",
        "child_parent_pagefile_view_api_write_$arch",
        "child_parent_pagefile_view_flush_$arch",
        "child_parent_pagefile_view_unmap_$arch",
        "child_parent_pagefile_view_unmap_interior_$arch"
    )
    $dll = Join-Path $repo "tests\fixtures\child_parent_module_$arch\companion_$arch.dll"
    foreach ($case in $cases) {
        $sample = Join-Path $repo "tests\fixtures\$case.exe"
        $caseOutput = Join-Path $OutputRoot $case
        & $runner run $sample --dll $dll --output $caseOutput --timeout 20 --max-instructions 200000 | Out-Null
        $expectedExit = if ($case -match '_view_(flush|unmap|unmap_interior)_') { 0 } else { 1 }
        if ($LASTEXITCODE -ne $expectedExit) {
            throw "${case}: expected exit $expectedExit, got $LASTEXITCODE"
        }
        Write-Output "${case}: denied"
    }
}

& $python $verifier $OutputRoot
if ($LASTEXITCODE -ne 0) {
    throw "Mapping-view verification failed in $OutputRoot"
}
Write-Output "Verified 18 packaged mapping-view cases in $OutputRoot"
