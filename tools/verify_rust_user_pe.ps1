param(
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][string]$Fixtures,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$fixturesPath=[IO.Path]::GetFullPath((Join-Path $repo $Fixtures))
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing evidence; choose fresh output.'}
$null=New-Item -ItemType Directory -Path $root
$records=@()
foreach($arch in @('X86','X64')) {
    foreach($case in @('exe','dll','tls','file','unsupported','exit')) {
        $name=if($case -eq 'dll'){'sample.dll'}else{'sample.exe'}
        $source=Join-Path $fixturesPath ($arch+'-'+$case+'/'+$name)
        $run=Join-Path $root ($arch+'-'+$case)
        & $exe run $source --output $run --max-instructions 20000 -- 'two words' 'tail\' *> ($run+'.console.log')
        $code=$LASTEXITCODE
        $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json
        $e=$manifest.result.execution
        $c=$manifest.result.containment
        if(-not $c.app_container -or -not $c.job_object -or -not $c.child_process_blocked -or $c.network_capabilities -ne 0){throw 'Containment missing'}
        if($manifest.cleanup -ne 'restored' -or $manifest.result.input_sha256 -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'Binding/cleanup changed'}
        if($e.configuration.generated_only -or -not $e.configuration.initialized -or $e.configuration.guest_image_path -ne ('C:\emumee\'+$name)){throw 'Submitted identity not installed'}
        if($case -eq 'unsupported') {
            if($code -ne 1 -or $null -eq $e.error -or $null -ne $e.guest_entry_return){throw 'Unsupported API must fail explicitly'}
        } elseif($case -eq 'exit') {
            if($code -ne 0 -or $e.completion_reason -ne 'process_exit' -or $e.process_exit_code -ne 256 -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Process exit code/termination changed'}
        } else {
            if($code -ne 0 -or $e.completion_reason -ne 'entry_return' -or $null -ne $e.error){throw "Execution failed $arch/$case : $($e.error)"}
            if($case -eq 'exe' -and ($e.guest_entry_return -ne 1000 -or $e.instruction_count -ne 3003)){throw 'EXE result/count changed'}
            if($case -eq 'dll' -and ($e.guest_entry_return -ne 1 -or $e.native_loader.events.Count -ne 2)){throw 'DLL startup changed'}
            if($case -eq 'tls' -and ($e.guest_entry_return -ne 42 -or $e.native_loader.events.Count -ne 1)){throw 'TLS startup changed'}
            if($case -eq 'file' -and $e.artifacts.Count -eq 0){throw 'File capture absent'}
        }
        $records+=@{architecture=$arch;case=$case;completion=$e.completion_reason;instructions=$e.instruction_count;verified=$true}
    }
    $source=Join-Path $fixturesPath ($arch+'-exe/sample.exe')
    $run=Join-Path $root ($arch+'-budget')
    & $exe run $source --output $run --max-instructions 32 *> ($run+'.console.log')
    if($LASTEXITCODE -ne 1){throw 'Budget stop must have failing CLI status'}
    $e=(Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json).result.execution
    if($e.instruction_count -ne 32 -or $e.completion_reason -ne 'instruction_budget' -or $null -ne $e.guest_entry_return){throw 'Exact budget changed'}
    $records+=@{architecture=$arch;case='budget';instructions=$e.instruction_count;verified=$true}
    $persona=Join-Path $root ($arch+'-persona.json')
    [IO.File]::WriteAllText($persona,'{"hostname":"RUST-USER-PE"}')
    $run=Join-Path $root ($arch+'-persona')
    & $exe run $source --output $run --persona $persona *> ($run+'.console.log')
    if($LASTEXITCODE -ne 0){throw 'Custom persona run failed'}
    $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json
    $request=Get-Content -LiteralPath (Join-Path $run 'request.json') -Raw | ConvertFrom-Json
    if($manifest.result.execution.configuration.input_json_sha256 -ne (Get-FileHash -LiteralPath $persona -Algorithm SHA256).Hash.ToLowerInvariant() -or $request.clock_utc_filetime -le 0){throw 'Persona/clock binding changed'}
    $records+=@{architecture=$arch;case='persona';verified=$true}
}
# Direct worker execution must refuse to read submitted bytes outside confinement.
$worker=Join-Path (Split-Path -Parent $exe) 'emumee-worker.exe'
& $worker --submitted-user $root ('a'*64) *> (Join-Path $root 'uncontained.log')
if($LASTEXITCODE -eq 0){throw 'Uncontained worker accepted submitted role'}
$source=Join-Path $fixturesPath 'X64-exe/sample.exe'
foreach($case in @('zero-budget','duplicate-budget','unknown-option')) {
    $run=Join-Path $root $case
    $options=switch($case) {
        'zero-budget' {@('--max-instructions','0')}
        'duplicate-budget' {@('--max-instructions','1','--max-instructions','2')}
        'unknown-option' {@('--bogus','value')}
    }
    & $exe run $source --output $run @options *> ($run+'.log')
    if($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $run)){throw "Rejected CLI input published a run: $case"}
}
$records | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained submitted PE cases and direct-worker refusal."
