param([string]$OutputRoot)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repo = Split-Path -Parent $PSScriptRoot
$runner = Join-Path $repo 'dist\Emumee\Emumee.exe'
$python = Join-Path $repo '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Build the packaged worker first: $runner"
}
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repo ('output\debug-check-' + [guid]::NewGuid().ToString('N'))
} elseif (-not [System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot = Join-Path $repo $OutputRoot
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) {
    throw "Choose a new output directory: $OutputRoot"
}
New-Item -ItemType Directory -Path $OutputRoot | Out-Null

foreach ($arch in @('x86', 'x64')) {
    foreach ($kind in @('remote_debug_check', 'is_debugger_present', 'peb_debug_check',
                        'nt_debug_port', 'nt_debug_object', 'nt_debug_flags')) {
        $case = "${kind}_${arch}"
        $sample = Join-Path $repo "tests\fixtures\$case.exe"
        & $runner run $sample --output (Join-Path $OutputRoot $case) `
            --timeout 60 --max-instructions 100000 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "${case}: expected exit 0, got $LASTEXITCODE"
        }
        Write-Output "${case}: completed"
    }
}

& $python (Join-Path $PSScriptRoot 'verify_debug_cases.py') $OutputRoot
if ($LASTEXITCODE -ne 0) { throw "Debug verification failed in $OutputRoot" }
Write-Output "Verified twelve packaged anti-debug cases in $OutputRoot"
