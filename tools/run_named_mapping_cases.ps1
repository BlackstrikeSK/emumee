param(
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repo = Split-Path -Parent $PSScriptRoot
$runner = Join-Path $repo 'dist\Emumee\Emumee.exe'
$python = Join-Path $repo '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Build the packaged worker first: $runner"
}
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repo ('output\named-mapping-check-' + [guid]::NewGuid().ToString('N'))
} elseif (-not [System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot = Join-Path $repo $OutputRoot
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) {
    throw "Choose a new output directory: $OutputRoot"
}
New-Item -ItemType Directory -Path $OutputRoot | Out-Null

foreach ($arch in @('x86', 'x64')) {
    foreach ($kind in @('named_pagefile_mapping', 'named_pagefile_coherent',
                        'named_pagefile_remap', 'named_pagefile_duplicate',
                        'child_parent_named_mapping',
                        'child_parent_named_mapping_foreign_read')) {
        $case = "${kind}_${arch}"
        $sample = Join-Path $repo "tests\fixtures\$case.exe"
        $caseOutput = Join-Path $OutputRoot $case
        if ($kind -like 'named_pagefile_*') {
            & $runner run $sample --output $caseOutput --timeout 20 --max-instructions 200000 | Out-Null
        } else {
            $dll = Join-Path $repo "tests\fixtures\child_parent_module_$arch\companion_$arch.dll"
            & $runner run $sample --dll $dll --output $caseOutput --timeout 20 --max-instructions 200000 | Out-Null
        }
        $expectedExit = 0
        if ($LASTEXITCODE -ne $expectedExit) {
            throw "${case}: expected exit $expectedExit, got $LASTEXITCODE"
        }
        Write-Output "${case}: expected outcome"
    }
}

& $python (Join-Path $PSScriptRoot 'verify_named_mapping.py') $OutputRoot
if ($LASTEXITCODE -ne 0) { throw "Named-mapping verification failed in $OutputRoot" }
Write-Output "Verified 12 packaged named-mapping cases in $OutputRoot"
