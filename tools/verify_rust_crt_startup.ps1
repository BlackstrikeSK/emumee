param(
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][string]$Fixtures,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$fixturesPath=[IO.Path]::GetFullPath((Join-Path $repo $Fixtures))
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing evidence; choose a fresh CRT startup root.'}
$null=New-Item -ItemType Directory -Path $root
$exe=Join-Path $bundlePath 'emumee-rs.exe'
$positive=@('arguments-narrow','arguments-wide','environment-narrow','environment-wide','initializers-void','initializers-error','initializers-fail','initializers-empty','initializers-mutate','legacy-arguments')
$records=@()
foreach($arch in @('X86','X64')) {
    $cases=Get-ChildItem -LiteralPath $fixturesPath -Directory | Where-Object {$_.Name.StartsWith($arch+'-')} | Sort-Object Name
    $expectedCases=if($arch -eq 'X86'){20}else{19}
    if($cases.Count -ne $expectedCases){throw "Expected $expectedCases exported startup controls for $arch"}
    foreach($case in $cases) {
        $kind=$case.Name.Substring(4)
        $run=Join-Path $root $case.Name
        $first=if($kind -eq 'wildcard'){'*.txt'}else{'two words'}
        & $exe run (Join-Path $case.FullName 'sample.exe') --output $run --max-instructions 20000 -- $first 'é😀' *> ($run+'.console.log')
        $code=$LASTEXITCODE
        $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json
        $e=$manifest.result.execution
        $c=$manifest.result.containment
        if(-not $c.app_container -or -not $c.job_object -or -not $c.child_process_blocked -or $c.network_capabilities -ne 0 -or $manifest.cleanup -ne 'restored'){throw 'CRT containment/cleanup changed'}
        if($positive -contains $kind) {
            if($code -ne 0 -or $null -ne $e.error -or $e.guest_entry_return -ne 1 -or $e.completion_reason -ne 'entry_return'){throw "CRT positive case failed $($case.Name): $($e.error)"}
            if($kind -ne 'initializers-empty' -and $e.crt_startup.initializer_pending){throw 'Completed startup retains pending callback'}
            if($kind -like 'initializers-*' -and $kind -ne 'initializers-empty') {
                $expected=if($kind -eq 'initializers-fail'){1}else{2}
                if($e.crt_startup.initializers.Count -ne $expected){throw 'Callback count/short-circuit changed'}
            }
        } else {
            if($code -ne 1 -or $null -eq $e.error -or $null -ne $e.guest_entry_return -or $e.completion_reason -ne 'error'){throw "CRT negative case fabricated success: $($case.Name)"}
        }
        $records+=@{architecture=$arch;case=$kind;completion=$e.completion_reason;instructions=$e.instruction_count;verified=$true}
    }
    $reference=Get-Content -LiteralPath (Join-Path $root ($arch+'-initializers-error/manifest.json')) -Raw | ConvertFrom-Json
    $budget=[long]$reference.result.execution.crt_startup.initializers[0].started_instruction+1
    $run=Join-Path $root ($arch+'-callback-budget')
    & $exe run (Join-Path $fixturesPath ($arch+'-initializers-error/sample.exe')) --output $run --max-instructions $budget -- 'two words' 'é😀' *> ($run+'.console.log')
    if($LASTEXITCODE -ne 1){throw 'Incomplete callback returned successful CLI status'}
    $e=(Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json).result.execution
    if($e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or -not $e.crt_startup.initializer_pending -or $null -ne $e.crt_startup.initializers[0].result -or $null -ne $e.guest_entry_return){throw 'Callback budget/result evidence changed'}
    $records+=@{architecture=$arch;case='callback-budget';instructions=$e.instruction_count;verified=$true}
}
$records | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained CRT startup controls."
