param(
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][string]$Fixtures,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [switch]$Layout,
    [switch]$Imports,
    [switch]$Abi
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
    if($Layout) {
        foreach($case in @('RawTail','VirtualTail','RawAlias','WriteData','WriteText','WriteHeaders','ExecuteData','ReadGap')) {
            $source=Join-Path $fixturesPath ($arch+'-layout-'+$case+'/layout.exe')
            $run=Join-Path $root ($arch+'-layout-'+$case)
            & $exe run $source --output $run --max-instructions 1000 *> ($run+'.console.log')
            $code=$LASTEXITCODE
            $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json
            $e=$manifest.result.execution
            $c=$manifest.result.containment
            if(-not $c.app_container -or -not $c.job_object -or -not $c.child_process_blocked -or $c.network_capabilities -ne 0){throw 'Layout containment missing'}
            if($manifest.cleanup -ne 'restored' -or $manifest.result.input_sha256 -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'Layout binding/cleanup changed'}
            if($e.configuration.generated_only -or -not $e.configuration.initialized -or $e.configuration.guest_image_path -ne 'C:\emumee\layout.exe'){throw 'Layout submitted identity absent'}
            $fault=switch($case) {
                'WriteText' {'WRITE_PROT'}
                'WriteHeaders' {'WRITE_PROT'}
                'ExecuteData' {'FETCH_PROT'}
                'ReadGap' {'READ_PROT'}
                default {$null}
            }
            if($fault) {
                if($code -ne 1 -or $null -ne $e.guest_entry_return -or $e.error -notmatch $fault){throw "Layout CPU protection failed: $arch/$case"}
            } else {
                $expectedReturn=if($case -eq 'VirtualTail'){0}else{42}
                if($code -ne 0 -or $e.completion_reason -ne 'entry_return' -or $null -ne $e.error -or $e.guest_entry_return -ne $expectedReturn){throw "Layout materialization failed: $arch/$case"}
            }
            $records+=@{architecture=$arch;case=('layout-'+$case);completion=$e.completion_reason;instructions=$e.instruction_count;verified=$true}
        }
    }
}
if($Abi) {
    $abiCases=@('Pow','Floor','FloorZero','Sin','SinZero','PowDomain','PowZero','PowOverflow','FloorNan','FloorInfinity','SinInfinity','Variadic','Variadic64','CrtCallback','CrtStack','CrtGpr','CrtVector','CrtDirection','CrtMxcsr','CrtFpcw','LoaderCallback','LoaderStack','LoaderGpr','LoaderVector','LoaderDirection','LoaderMxcsr','LoaderFpcw')
    $positive=@('Pow','Floor','FloorZero','Sin','SinZero','Variadic','Variadic64','CrtCallback','LoaderCallback')
    foreach($arch in @('X86','X64')) {
        foreach($case in $abiCases) {
            if($arch -eq 'X86' -and $case -in @('CrtVector','LoaderVector')){continue}
            $source=Join-Path $fixturesPath ($arch+'-abi-'+$case+'/abi.exe')
            $run=Join-Path $root ($arch+'-abi-'+$case)
            & $exe run $source --output $run --max-instructions 4000 *> ($run+'.console.log')
            $code=$LASTEXITCODE
            $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json
            $e=$manifest.result.execution
            $c=$manifest.result.containment
            if(-not $c.app_container -or -not $c.job_object -or -not $c.child_process_blocked -or $c.network_capabilities -ne 0){throw 'ABI containment missing'}
            if($manifest.cleanup -ne 'restored' -or $manifest.result.input_sha256 -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'ABI binding/cleanup changed'}
            if($e.configuration.generated_only -or -not $e.configuration.initialized -or $e.configuration.guest_image_path -ne 'C:\emumee\abi.exe'){throw 'ABI submitted identity absent'}
            if($case -in $positive) {
                $expected=if($case -eq 'LoaderCallback'){42}elseif($case -in @('Variadic','Variadic64')){17}else{1}
                if($code -ne 0 -or $e.completion_reason -ne 'entry_return' -or $null -ne $e.error -or $e.guest_entry_return -ne $expected){throw "ABI guest control failed: $arch/$case : $($e.error)"}
            } else {
                $reason=switch -Regex ($case) {
                    '^CrtStack$' {'return frame'}
                    '^LoaderStack$' {'stack return contract'}
                    'Gpr$' {'nonvolatile register'}
                    'Vector$' {'vector register'}
                    'Direction$' {'flags'}
                    'Mxcsr$' {'MXCSR'}
                    'Fpcw$' {'FPCW'}
                    '^PowDomain$' {'complex'}
                    '^PowZero$' {'negative power'}
                    '^PowOverflow$' {'overflow'}
                    '^Floor' {'nonfinite'}
                    '^SinInfinity$' {'domain'}
                }
                if($code -ne 1 -or $null -ne $e.guest_entry_return -or -not $reason -or $e.error -notmatch [regex]::Escape($reason)){throw "ABI refusal failed: $arch/$case : $($e.error)"}
            }
            $records+=@{architecture=$arch;case=('abi-'+$case);completion=$e.completion_reason;instructions=$e.instruction_count;verified=$true}
        }
    }
}
# Direct worker execution must refuse to read submitted bytes outside confinement.
if($Imports) {
    foreach($arch in @('X86','X64')) {
        foreach($case in @('ApiSet','DelayPid','DelayMissing','DelayUnused','DelayFlags','DelayAttributes','DelayModule','DelayDescriptor','DelayDll','DelayIat','DelayUnaligned','DelayLimit','DelayNames','DelayEmpty','DelayOrdinal','DelayHint','DelayName','DelayWrite')) {
            $source=Join-Path $fixturesPath ($arch+'-imports-'+$case+'/imports.exe')
            $run=Join-Path $root ($arch+'-imports-'+$case)
            & $exe run $source --output $run --max-instructions 2000 *> ($run+'.console.log')
            $code=$LASTEXITCODE
            $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json
            $e=$manifest.result.execution
            $c=$manifest.result.containment
            if(-not $c.app_container -or -not $c.job_object -or -not $c.child_process_blocked -or $c.network_capabilities -ne 0){throw 'Imports containment missing'}
            if($manifest.cleanup -ne 'restored' -or $manifest.result.input_sha256 -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'Imports binding/cleanup changed'}
            if($e.configuration.generated_only -or -not $e.configuration.initialized -or $e.configuration.guest_image_path -ne 'C:\emumee\imports.exe'){throw 'Imports submitted identity absent'}
            $expectedReturn=switch($case){'DelayPid'{1024};'ApiSet'{42};'DelayUnused'{42};default{0}}
            if($code -ne 0 -or $e.completion_reason -ne 'entry_return' -or $null -ne $e.error -or $e.guest_entry_return -ne $expectedReturn){throw "Imports execution failed: $arch/$case"}
            if($case -in @('ApiSet','DelayUnused')) {
                if(@($e.delay_imports).Count -ne 0){throw 'Imports were resolved eagerly'}
            } else {
                if(@($e.delay_imports).Count -ne 1){throw 'Delay observation absent'}
                $row=$e.delay_imports[0]
                if($case -eq 'DelayPid') {
                    if($null -ne $row.error -or $null -eq $row.target -or $row.target -eq 0){throw 'Delay target not resolved'}
                } elseif($null -eq $row.error -or $null -ne $row.target){throw 'Delay refusal evidence absent'}
            }
            if($e.delay_imports_omitted -ne 0){throw 'Unexpected delay observation loss'}
            $records+=@{architecture=$arch;case=('imports-'+$case);completion=$e.completion_reason;instructions=$e.instruction_count;verified=$true}
        }
    }
}
$worker=Join-Path (Split-Path -Parent $exe) 'emumee-worker.exe'
$refusalErrorPreference=$ErrorActionPreference
try {
    $ErrorActionPreference='Continue'
    $LASTEXITCODE=$null
    & $worker --submitted-user $root ('a'*64) *> (Join-Path $root 'uncontained.log')
    $code=$LASTEXITCODE
} finally {$ErrorActionPreference=$refusalErrorPreference}
if($null -eq $code -or $code -ne 2){throw 'Uncontained worker did not return the expected refusal status'}
if((Get-Content -LiteralPath (Join-Path $root 'uncontained.log') -Raw) -notmatch 'outside AppContainer'){throw 'Uncontained worker failed for an unexpected reason'}
$refusals=@(@{case='uncontained-worker';exit_code=$code;verified=$true})
if($Layout) {
    foreach($arch in @('X86','X64')) {
        foreach($case in @('Headers','Raw','Overlap')) {
            $source=Join-Path $fixturesPath ($arch+'-layout-invalid-'+$case+'/layout.exe')
            $run=Join-Path $root ($arch+'-layout-invalid-'+$case)
            try {
                $ErrorActionPreference='Continue'
                $LASTEXITCODE=$null
                & $exe run $source --output $run *> ($run+'.log')
                $code=$LASTEXITCODE
            } finally {$ErrorActionPreference=$refusalErrorPreference}
            $reason=switch($case) {
                'Headers' {'misaligned image/header size'}
                'Raw' {'misaligned section file offset'}
                'Overlap' {'overlapping sections'}
            }
            if($null -eq $code -or $code -ne 2 -or (Test-Path -LiteralPath $run)){throw "Malformed layout published a run: $arch/$case"}
            if((Get-Content -LiteralPath ($run+'.log') -Raw) -notmatch [regex]::Escape($reason)){throw "Layout refusal reason changed: $arch/$case"}
            $refusals+=@{architecture=$arch;case=('layout-'+$case);exit_code=$code;verified=$true}
        }
    }
}
if($Imports) {
    foreach($arch in @('X86','X64')) {
        foreach($case in @('module','empty','hint','ordinal','iat_gap','iat_end','descriptor','alias','partial_alias')) {
            $source=Join-Path $fixturesPath ($arch+'-imports-invalid-'+$case+'/imports.exe')
            $run=Join-Path $root ($arch+'-imports-invalid-'+$case)
            try {
                $ErrorActionPreference='Continue'
                $LASTEXITCODE=$null
                & $exe run $source --output $run *> ($run+'.log')
                $code=$LASTEXITCODE
            } finally {$ErrorActionPreference=$refusalErrorPreference}
            if($null -eq $code -or $code -ne 2 -or (Test-Path -LiteralPath $run)){throw "Malformed imports published a run: $arch/$case"}
            $reason=switch($case) {
                'module' {'invalid import module/IAT'}
                'empty' {'empty import name'}
                'hint' {'RVA exceeds image'}
                'ordinal' {'reserved ordinal thunk bits'}
                'iat_gap' {'IAT is outside mapped image ranges'}
                'iat_end' {'IAT exceeds image'}
                'descriptor' {'unterminated import descriptors'}
                default {'overlapping import IAT slots'}
            }
            if((Get-Content -LiteralPath ($run+'.log') -Raw) -notmatch [regex]::Escape($reason)){throw "Import admission reason changed: $arch/$case"}
            $refusals+=@{architecture=$arch;case=('imports-'+$case);exit_code=$code;verified=$true}
        }
    }
}
$source=Join-Path $fixturesPath 'X64-exe/sample.exe'
foreach($case in @('zero-budget','duplicate-budget','unknown-option')) {
    $run=Join-Path $root $case
    $options=switch($case) {
        'zero-budget' {@('--max-instructions','0')}
        'duplicate-budget' {@('--max-instructions','1','--max-instructions','2')}
        'unknown-option' {@('--bogus','value')}
    }
    try {
        $ErrorActionPreference='Continue'
        $LASTEXITCODE=$null
        & $exe run $source --output $run @options *> ($run+'.log')
        $code=$LASTEXITCODE
    } finally {$ErrorActionPreference=$refusalErrorPreference}
    if($null -eq $code -or $code -ne 2 -or (Test-Path -LiteralPath $run)){throw "Rejected CLI input returned the wrong status or published a run: $case"}
    $expectedReason=switch($case) {
        'zero-budget' {'Submitted PE execution budget outside profile'}
        'duplicate-budget' {'--max-instructions given twice'}
        'unknown-option' {'Unknown run option: --bogus'}
    }
    if((Get-Content -LiteralPath ($run+'.log') -Raw) -notmatch [regex]::Escape($expectedReason)){throw "CLI refusal reason changed: $case"}
    $refusals+=@{case=$case;exit_code=$code;verified=$true}
}
[IO.File]::WriteAllText((Join-Path $root 'verification.json'),($records | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $root 'refusal-verification.json'),($refusals | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output "Verified $($records.Count) contained submitted PE cases and direct-worker refusal."
