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
    $OutputRoot = Join-Path $repo ('output\duplicate-file-check-' + [guid]::NewGuid().ToString('N'))
} elseif (-not [System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot = Join-Path $repo $OutputRoot
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) {
    throw "Choose a new output directory: $OutputRoot"
}
New-Item -ItemType Directory -Path $OutputRoot | Out-Null

foreach ($arch in @('x86', 'x64')) {
    $case = "duplicate_guest_file_$arch"
    $sample = Join-Path $repo "tests\fixtures\$case.exe"
    $caseOutput = Join-Path $OutputRoot $case
    & $runner run $sample --output $caseOutput --timeout 20 --max-instructions 100000 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "${case}: expected exit 0, got $LASTEXITCODE"
    }
    Write-Output "${case}: expected outcome"
}

& $python (Join-Path $PSScriptRoot 'verify_duplicate_guest_file.py') $OutputRoot
if ($LASTEXITCODE -ne 0) { throw "Guest-file duplicate verification failed in $OutputRoot" }
Write-Output "Verified 2 packaged guest-file duplicate cases in $OutputRoot"
