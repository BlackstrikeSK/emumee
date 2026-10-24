param(
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [switch]$ModeledObjectControls,
    [switch]$TypedKernelData,
    [switch]$ModeledWaitControls,
    [switch]$Resume
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'assert_rust_default_kernel_metadata.ps1')
$bundlePath = [System.IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$root = [System.IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if (Test-Path -LiteralPath $root) {
    if (-not $Resume) { throw 'Verification root must be new, or explicitly resume verified generated results.' }
} else { $null = New-Item -ItemType Directory -Path $root }
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$protectedDataSymbol = if($ModeledObjectControls){'MmSystemRangeStart'}else{'PsInitialSystemProcess'}
$protectedCodeSymbol = if($ModeledWaitControls){'KeInsertQueueDpc'}else{'KeDelayExecutionThread'}
$cases = @(
    @{kind='kernel-catalog-call'; error='FETCH_PROT'; calls=1; cpu_error=$true; only_arch='x64'; providers=2; catalog_symbol=$protectedCodeSymbol; catalog_kind='code'; catalog_access='execute'},
    @{kind='kernel-catalog-code-read'; error='READ_PROT'; calls=1; cpu_error=$true; only_arch='x64'; providers=2; catalog_symbol=$protectedCodeSymbol; catalog_kind='code'; catalog_access='read'},
    @{kind='kernel-catalog-data-read'; error='READ_PROT'; calls=1; cpu_error=$true; only_arch='x64'; providers=2; catalog_symbol=$protectedDataSymbol; catalog_kind='data'; catalog_access='read'},
    @{kind='pool-lifecycle'; value=1; calls=4; pool_allocations=2; pool_frees=2; pool_live=0},
    @{kind='pool-lifecycle'; name='pool-lifecycle-before-return'; budget='before-return'; cpu_budget=$true},
    @{kind='pool-executable'; value=1; calls=2; pool_allocations=1; pool_frees=1; pool_live=0},
    @{kind='pool-executable'; name='pool-executable-before-return'; budget='before-return'; cpu_budget=$true},
    @{kind='pool-too-large'; value=0; calls=1; pool_allocations=0; pool_frees=0; pool_live=0},
    @{kind='pool-too-large'; name='pool-too-large-before-return'; budget='before-return'; cpu_budget=$true},
    @{kind='pool-nx-execute'; error='FETCH_PROT'; calls=1; cpu_error=$true; pool_allocations=1; pool_frees=0; pool_live=1},
    @{kind='pool-freed-read'; error='READ_UNMAPPED'; calls=2; cpu_error=$true; pool_allocations=1; pool_frees=1; pool_live=0},
    @{kind='pool-bad-tag'; error='tag mismatch'; calls=2; pool_allocations=1; pool_frees=0; pool_live=1},
    @{kind='pool-paged-irql'; error='IRQL'; calls=2; pool_allocations=0; pool_frees=0; pool_live=0},
    @{kind='pool-bad-flags'; error='flags are not modeled'; calls=1; pool_allocations=0; pool_frees=0; pool_live=0},
    @{kind='pool-double-free'; error='live pool allocation'; calls=3; pool_allocations=1; pool_frees=1; pool_live=0},
    @{kind='kernel-resolve'; value=1; calls=2; providers=2; provider_call=$true},
    @{kind='kernel-resolve'; name='kernel-resolve-before-return'; budget='before-return'; cpu_budget=$true; providers=2},
    @{kind='kernel-resolve-bad-length'; error='UNICODE_STRING'; calls=1; providers=2},
    @{kind='kernel-resolve-irql'; error='PASSIVE_LEVEL'; calls=2; providers=2},
    @{kind='kernel-resolve-unknown'; error='availability is not established'; calls=1; providers=2},
    @{kind='user-resolve-a'; value=1024; calls=3; providers=4; provider_call=$true},
    @{kind='user-resolve-a'; name='user-resolve-a-before-return'; budget='before-return'; cpu_budget=$true; providers=4},
    @{kind='user-resolve-w'; value=1024; calls=3; providers=4; provider_call=$true},
    @{kind='user-resolve-w'; name='user-resolve-w-before-return'; budget='before-return'; cpu_budget=$true; providers=4},
    @{kind='user-resolve-unknown'; error='availability is not established'; calls=2; providers=4},
    @{kind='user-resolve-bad-module'; value=126; calls=3; providers=4},
    @{kind='user-resolve-bad-module'; name='user-resolve-bad-module-before-return'; budget='before-return'; cpu_budget=$true; providers=4},
    @{kind='user-api'; value=0x12345678; calls=5},
    @{kind='kernel-api-address'; value=1; calls=1; api_space='kernel'},
    @{kind='user-api-address'; value=1; calls=1; api_space='user'},
    @{kind='copy'; value=0x54535552; calls=1},
    @{kind='debug-prompt'; value=0x52525252; calls=1},
    @{kind='copy-to-code'; error='lacks permission'; calls=1},
    @{kind='prompt-to-code'; error='lacks permission'; calls=1},
    @{kind='unsupported-import'; error='Unsupported Windows API'; calls=1},
    @{kind='virtual-memory'; value=0; calls=8},
    @{kind='virtual-bad-protect-output'; value=0x54535552; calls=2},
    @{kind='virtual-recommit'; value=0x54535552; calls=3},
    @{kind='virtual-write-protected'; error='WRITE_PROT'; calls=2; cpu_error=$true},
    @{kind='virtual-released-read'; error='READ_UNMAPPED'; calls=2; cpu_error=$true},
    @{kind='virtual-reserve-read'; error='READ_PROT'; calls=1; cpu_error=$true},
    @{kind='linked-module'; value=17; calls=0; modules=2},
    @{kind='forwarded-module'; value=17; calls=0; modules=3},
    @{kind='file-round-trip-a'; value=0x54535552; calls=6; file=$true},
    @{kind='file-round-trip-w'; value=0x54535552; calls=6; file=$true},
    @{kind='file-read-only'; value=5; calls=3; file_failure=5; failure_index=1},
    @{kind='file-read-code'; value=998; calls=5; file_failure=998; failure_index=3; file=$true},
    @{kind='guarded-mutex'; value=1; calls=7; kernel=$true},
    @{kind='guarded-busy'; error='scheduling is required'; calls=2},
    @{kind='guarded-bad-release'; error='does not own'; calls=2},
    @{kind='guarded-irql'; error='above APC_LEVEL'; calls=3},
    @{kind='critical-underflow'; error='underflow'; calls=1},
    @{kind='system-thread'; value=0; calls=2; threads=$true},
    @{kind='system-thread-return'; value=0; calls=1; threads=$true},
    @{kind='system-thread-bad-start'; error='argument range'; calls=1},
    @{kind='system-thread'; name='system-thread-budget32'; budget=32},
    @{kind='system-thread'; name='system-thread-budget270'; budget=270},
    @{kind='mutex-handoff'; value=1; calls=8; threads=$true; kernel=$true; handoff=$true},
    @{kind='mutex-deadlock'; error='deadlock'; calls=7; scheduler_error=$true; deadlock=$true},
    @{kind='mutex-handoff'; name='mutex-handoff-budget300'; budget=300},
    @{kind='mutex-handoff'; name='mutex-handoff-before-return'; budget='before-return'},
    @{kind='cpu-identity'; value=1; calls=0; cpu='identity'},
    @{kind='cpu-time'; value=1; calls=0; cpu='time'},
    @{kind='cpu-rewrite'; value=1; calls=0; cpu='rewrite'},
    @{kind='cpu-bad-xcr'; error='XGETBV index'; calls=0; cpu_error=$true},
    @{kind='cpu-halt'; error='halted'; calls=0; cpu_error=$true},
    @{kind='cpu-tsc-aux'; value=1; calls=0; tsc_aux=$true},
    @{kind='thread-msr'; value=0x12345678; calls=1; threads=$true; msr_context=$true},
    @{kind='cpu-tsc-msr-read'; value=1; calls=0; tsc_reads=1; tsc_writes=0},
    @{kind='cpu-tsc-msr-write'; value=1; calls=0; tsc_reads=0; tsc_writes=1},
    @{kind='cpu-tsc-msr-wrap'; value=1; calls=0; tsc_reads=0; tsc_writes=1},
    @{kind='cpu-tsc-adjust'; value=1; calls=0; tsc_reads=1; tsc_writes=1; adjust_expected=3000},
    @{kind='cpu-tsc-adjust-link'; value=1; calls=0; tsc_reads=1; tsc_writes=1},
    @{kind='cpu-tsc-adjust-reset'; value=1; calls=0; tsc_reads=0; tsc_writes=2; adjust_expected=0},
    @{kind='cpu-tsc-msr-user'; error='CPL0 driver context'; calls=0; cpu_error=$true; tsc_reads=0; tsc_writes=0},
    @{kind='thread-tsc'; value=1; calls=1; threads=$true; tsc_reads=1; tsc_writes=1; counter_thread=$true},
    @{kind='kernel-syscall'; value=1; calls=0; only_arch='x64'; syscall=$true},
    @{kind='kernel-syscall'; name='kernel-syscall-x86-refusal'; error='Unmodeled SYSCALL'; calls=0; cpu_error=$true; only_arch='x86'; rejected_entry=$true},
    @{kind='kernel-syscall-bad-target'; error='not executable guest code'; calls=0; cpu_error=$true; only_arch='x64'; rejected_entry=$true},
    @{kind='kernel-sysret'; error='Unmodeled SYSRET'; calls=0; cpu_error=$true; rejected_entry=$true},
    @{kind='kernel-sysenter'; error='Unmodeled SYSENTER'; calls=0; cpu_error=$true; rejected_entry=$true},
    @{kind='kernel-sysexit'; error='Unmodeled SYSEXIT'; calls=0; cpu_error=$true; rejected_entry=$true},
    @{kind='cpu-time'; name='cpu-time-before-return'; budget='before-return'; cpu_budget=$true},
    @{kind='kernel-cpu'; value=1; calls=0; boot=$true},
    @{kind='kernel-entry'; value=1; calls=0; boot=$true; kernel_entry=$true},
    @{kind='kernel-relocated'; value=17; calls=0; relocated=$true},
    @{kind='kernel-relocated'; name='kernel-relocated-before-return'; budget='before-return'; cpu_budget=$true},
    @{kind='kernel-write-protected'; error='WRITE_PROT'; calls=0; cpu_error=$true; boot=$true},
    @{kind='user-time'; value=1; calls=5; time=$true},
    @{kind='kernel-time'; value=1; calls=4; time=$true; boot=$true},
    @{kind='time-bad-output'; value=998; calls=2; time_bad=$true},
    @{kind='shared-time'; value=1; calls=0},
    @{kind='shared-time-write'; error='WRITE_PROT'; calls=0; cpu_error=$true},
    @{kind='event-auto'; value=1; calls=7},
    @{kind='event-manual'; value=1; calls=7},
    @{kind='event-timeout'; value=0x102; calls=2; event_timeout=$true},
    @{kind='event-absolute'; value=0x102; calls=2; event_timeout=$true},
    @{kind='event-long-timeout'; value=0x102; calls=2; event_timeout=$true; day_timeout=$true},
    @{kind='event-deadlock'; error='deadlock'; calls=2; scheduler_error=$true; event_deadlock=$true},
    @{kind='event-handoff'; value=1; calls=5; event_handoff=$true; threads=$true},
    @{kind='event-irql'; error='above APC_LEVEL'; calls=3},
    @{kind='event-alertable'; error='non-alertable'; calls=2},
    @{kind='event-tamper'; error='diverges'; calls=2},
    @{kind='event-handoff'; name='event-handoff-before-return'; budget='before-return'},
    @{kind='event-timeout'; name='event-timeout-before-return'; budget='before-return'; cpu_budget=$true}
)
$records = @()
foreach ($arch in @('x86','x64')) {
    foreach ($case in $cases) {
        if($case.only_arch -and $case.only_arch -ne $arch) {continue}
        $caseName=if($case.name){$case.name}else{$case.kind}
        $budget=if($case.budget -eq 'before-return') {
            $baseline=@($records | Where-Object {$_.arch -eq $arch -and $_.kind -eq $case.kind -and $_.exit_code -eq 0})
            if($baseline.Count -ne 1){throw 'Missing completed baseline for final-instruction budget control.'}
            $baseline[0].instructions-1
        } elseif($case.budget){$case.budget}else{10000}
        $run = Join-Path $root "$arch-$caseName"
        $reused=$false
        if(Test-Path -LiteralPath $run){
            if(-not $Resume){throw 'Refuse to overwrite existing generated run.'}
            $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
            $console=Get-Content -LiteralPath "$run.console.log" -Raw|ConvertFrom-Json
            if(($console|ConvertTo-Json -Depth 100 -Compress) -cne ($manifest|ConvertTo-Json -Depth 100 -Compress)){throw 'Resume controller stdout differs from saved manifest.'}
            $requestPath=Join-Path $run 'request.json'
            $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
            $requestHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $requestPath).Hash.ToLowerInvariant()
            $resultHash=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $run 'fixture-result.json')).Hash.ToLowerInvariant()
            $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
            foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Resume run belongs to another frozen build.'}}
            if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $request.kind -ne $case.kind -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget){throw 'Resume request/result/cleanup binding failed.'}
            $saved=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
            if($saved.request_sha256 -cne $requestHash){throw 'Resume result request hash changed.'}
            $exit=if($saved.execution.completion_reason -eq 'entry_return'){0}else{1}
            $reused=$true
        }else{
            & (Join-Path $bundlePath 'emumee-rs.exe') fixture --arch $arch --kind $case.kind --max-instructions $budget --isolated-output $run *> "$run.console.log"
            $exit = $LASTEXITCODE
        }
        $result = Get-Content -Raw -LiteralPath (Join-Path $run 'fixture-result.json') | ConvertFrom-Json
        $execution = $result.execution
        if($case.catalog_symbol) {
            $denials=@($execution.provider_denials)
            if($denials.Count -ne 1 -or $denials[0].name -ne $case.catalog_symbol -or $denials[0].kind -ne $case.catalog_kind -or $denials[0].access -ne $case.catalog_access -or $denials[0].offset -ne 0 -or $execution.api_events[0].result -eq 0 -or $null -eq $execution.api_events[0].result) {throw 'Classified symbol lookup/access evidence is inconsistent.'}
        }
        if($case.ContainsKey('pool_live')) {
            $pool=$execution.kernel_pool
            if($null -eq $pool -or $pool.total_allocations -ne $case.pool_allocations -or $pool.total_frees -ne $case.pool_frees -or @($pool.allocations.PSObject.Properties).Count -ne $case.pool_live) {throw 'Kernel pool lifecycle evidence is inconsistent.'}
            if($case.pool_live -eq 0 -and $pool.mapped_bytes -ne 0) {throw 'Freed kernel pool backing remains reserved.'}
            if($execution.architecture -eq 'x86' -and $execution.api_events[0].api -eq 'ntoskrnl.ExAllocatePool2' -and ($execution.api_events[0].arguments.Count -ne 4 -or $execution.api_events[0].arguments[3] -ne 0x54535552L)) {throw 'x86 POOL_FLAGS argument shifted size/tag decoding.'}
        }
        if($case.providers) {
            $expectedProviders=$case.providers+$(if($execution.kernel_cpu){6}else{0})
            if($execution.kernel_cpu){Assert-RustDefaultKernelMetadata -Execution $execution -Architecture $arch}
            if($execution.synthetic_providers.Count -ne $expectedProviders -or $execution.loaded_modules.Count -ne ($expectedProviders+1)) {throw 'Synthetic provider image evidence is incomplete.'}
            foreach($provider in $execution.synthetic_providers) {
                $module=@($execution.loaded_modules | Where-Object {$_.name -eq $provider.module -and [decimal]$_.base -eq [decimal]$provider.base})
                if($module.Count -ne 1 -or $module[0].size -ne $provider.image_size -or ($provider.exports -lt 1 -and $null -eq $provider.metadata_only) -or $provider.scope -notlike '*Synthetic guest PE*') {throw 'Provider PE mapping/profile mismatch.'}
                if($provider.reference_catalog) {
                    $catalog=$provider.reference_catalog
                    # append_kernel_lock_storage places .emulock exactly after the protected catalog.
                    # The dedicated core fixture parses its RVA, 4096-byte size and RW/NX section flags.
                    $expectedLockRva=$catalog.protected_rva+$catalog.protected_size
                    $expectedLockSize=4096
                    if($arch -ne 'x64' -or $catalog.reference_code_symbols -ne 3180 -or $catalog.reference_data_symbols -ne 77 -or $provider.exports -ne (3257+$catalog.modeled_extensions.Count) -or $catalog.protected_size -ne ($catalog.protected_symbols*4096) -or $provider.image_size -ne ($expectedLockRva+$expectedLockSize) -or $catalog.scope -notlike '*PRCB lock backing uses a separate RW/NX page*' -or $provider.image_size -ge 16777216) {throw 'Kernel reference classification/profile bounds changed.'}
                } else {
                    $expectedSize=if($arch -eq 'x86' -and $provider.module -eq 'ntoskrnl.exe'){28672}else{24576}
                    if($provider.image_size -ne $expectedSize){throw 'Partial provider size changed.'}
                }
            }
            if($case.provider_call) {
                $base=[decimal]$execution.synthetic_providers[0].base
                $eventIndex=if($case.kind -eq 'kernel-resolve'){0}else{1}
                $address=[decimal]$execution.api_events[$eventIndex].result
                if($address -lt ($base+4096) -or $address -ge ($base+8192) -or @($execution.instruction_tail | Where-Object {[decimal]$_.pc -eq $address}).Count -lt 1) {throw 'Dynamic call bypassed its resolved PE provider export.'}
            }
        }
        if($case.relocated) {
            $expectedImageBase=if($arch -eq 'x64'){[UInt64]::Parse('fffff80100000000',[Globalization.NumberStyles]::HexNumber)}else{[UInt64]0x90000000L}
            if(-not $execution.image_load.relocated -or [decimal]$execution.image_load.base -ne [decimal]$expectedImageBase -or [decimal]$execution.loaded_modules[0].base -ne [decimal]$expectedImageBase -or [decimal]$execution.instruction_tail[0].pc -ne ([decimal]$expectedImageBase+4096)) {throw 'Driver code/metadata did not use its relocated kernel image.'}
        }
        if($case.api_space) {
            $expectedBase=if($case.api_space -eq 'user'){[UInt64]0x68000000L}elseif($arch -eq 'x86'){[UInt64]0x82000000L}else{[UInt64]::Parse('fffff80200000000',[Globalization.NumberStyles]::HexNumber)}
            if([decimal]$execution.api_region.base -ne [decimal]$expectedBase -or $execution.api_region.size -ne 65536 -or $execution.api_region.bindings -ne 1) {throw 'API gate address domain is incorrect.'}
        }
        if($case.ContainsKey('tsc_reads') -and ($execution.cpu.tsc_msr_reads -ne $case.tsc_reads -or $execution.cpu.tsc_msr_writes -ne $case.tsc_writes)) {throw 'TSC MSR access did not use the virtual counter model.'}
        if($case.ContainsKey('adjust_expected') -and ($execution.virtual_tsc_offset -ne $case.adjust_expected -or $execution.virtual_tsc_adjust -ne $case.adjust_expected)) {throw 'TSC_ADJUST and virtual counter offset diverged.'}
        if($case.counter_thread -and ($execution.virtual_tsc_offset -eq 0 -or $execution.kernel_cpu.msr_context_repairs -ne 0)) {throw 'Virtual TSC offset was lost or stored in native thread context.'}
        if($case.rejected_entry -and ($execution.kernel_cpu.system_entry_attempts -ne 1 -or $execution.kernel_cpu.system_entry_tail.Count -ne 1 -or $execution.kernel_cpu.system_entry_tail[0].accepted)) {throw 'Rejected system entry lacks explicit evidence.'}
        if($case.syscall -and ($execution.kernel_cpu.system_entry_attempts -ne 1 -or -not $execution.kernel_cpu.system_entry_tail[0].accepted -or $execution.kernel_cpu.system_entry_tail[0].target -ne 0x140001180)) {throw 'Guest LSTAR transition was not executed.'}
        if($execution.kernel_cpu) {
            $cpu=$execution.kernel_cpu
            if($cpu.initial.cr0 -ne 0x80050033L -or ($cpu.initial.cs -band 3) -ne 0 -or
               $cpu.pcr_current_thread -ne $cpu.current_thread -or $cpu.pcr_irql -ne $execution.kernel_state.irql) {throw 'Kernel CPU/PCR context is inconsistent.'}
            $entry=$execution.kernel_entry
            if(-not $entry -or $entry.layout.root_thread -eq $entry.layout.registry_path -or $entry.entry_stack_size -ne 1048576 -or $entry.driver_object_size -ne $(if($arch -eq 'x64'){336}else{168})) {throw 'Driver entry structures are inconsistent.'}
            if($arch -eq 'x64') {
                $floor=[decimal]([UInt64]::Parse('ffff800000000000',[Globalization.NumberStyles]::HexNumber))
            } else {$floor=[decimal]0x80000000L}
            foreach($pointer in @($entry.layout.entry_stack,$entry.layout.driver_object,$entry.layout.registry_path,$entry.layout.root_thread,$entry.layout.descriptor_tables,$entry.layout.return_marker,$cpu.gdt,$cpu.idt,$cpu.pcr_current_thread)) {
                if([decimal]$pointer -lt $floor){throw 'Kernel pointer was placed in user space.'}
            }
        } elseif($case.boot) {throw 'Missing kernel boot context.'}
        if (-not $result.containment.app_container -or -not $result.containment.job_object -or
            -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0) {
            throw "Containment failure: $run"
        }
        if (($case.ContainsKey('calls') -and $execution.api_calls -ne $case.calls) -or $execution.api_events_omitted -ne 0) { throw "API event count: $run" }
        if($case.budget) {
            if($exit -ne 1 -or $execution.completion_reason -ne 'instruction_budget' -or $execution.instruction_count -ne $budget -or $null -ne $execution.guest_entry_return) {throw 'Global system-thread instruction budget was not enforced.'}
            if(-not $case.cpu_budget -and ($execution.kernel_threads.count -ne 2 -or $null -ne $execution.kernel_threads.root_entry_return)) {throw 'Budget stop misreported thread completion.'}
        } elseif ($case.ContainsKey('error')) {
            if ($exit -ne 1 -or $execution.completion_reason -ne 'error' -or $null -ne $execution.guest_entry_return -or
                $execution.error -notlike "*$($case.error)*") { throw "Negative control failed: $run" }
            if (-not $case.cpu_error -and -not $case.scheduler_error -and -not $execution.api_events[-1].error) { throw "Missing API failure event: $run" }
            if($case.deadlock -and ($execution.kernel_threads.waits -ne 2 -or $execution.kernel_threads.resumed_waits -ne 0 -or @($execution.api_events | Where-Object {$_.pending}).Count -ne 2)) {throw 'Cyclic mutex waits received a false completion.'}
            if($case.event_deadlock -and ($execution.kernel_threads.waits -ne 1 -or $execution.kernel_threads.resumed_waits -ne 0 -or -not $execution.api_events[-1].pending)) {throw 'Deadlocked event wait received a fake completion.'}
        } else {
            if ($exit -ne 0 -or $execution.completion_reason -ne 'entry_return' -or $execution.guest_entry_return -ne $case.value) { throw "Guest return mismatch: $run" }
            if ($case.kind -eq 'user-api' -and $execution.virtual_uptime_ms -lt 523812025) { throw 'Guest Sleep did not advance virtual time.' }
            if($case.time -and $null -ne $execution.api_events[-1].result) {throw 'Void time API fabricated a return value.'}
            if($case.time_bad -and ($execution.api_events[0].result -ne 0 -or $execution.api_events[0].last_error -ne 998)) {throw 'Counter wrote into an RX output buffer.'}
            if($case.event_timeout -and ($execution.virtual_uptime_ms -lt 523812025 -or $execution.kernel_threads.waits -ne 1 -or $execution.kernel_threads.resumed_waits -ne 1 -or $execution.api_events[-1].effect -ne 'wait_timeout' -or $execution.api_events[-1].pending)) {throw 'Virtual event timeout did not resume with STATUS_TIMEOUT.'}
            if($case.day_timeout -and $execution.virtual_uptime_ms -lt (523812000+86400000)) {throw 'Day-long event wait did not advance virtual time.'}
            if($case.event_handoff -and ($execution.kernel_threads.waits -ne 1 -or $execution.kernel_threads.resumed_waits -ne 1 -or @($execution.api_events | Where-Object {$_.effect -eq 'event_signaled'}).Count -ne 1 -or @($execution.api_events | Where-Object {$_.pending}).Count -ne 0)) {throw 'Guest event was not signaled by its actual peer thread.'}
            if ($case.cpu) {
                $expected=switch($case.cpu){'identity'{@(5,0,0,0)} 'time'{@(0,1,1,1)} 'rewrite'{@(1,1,0,0)}}
                $actual=@($execution.cpu.cpuid,$execution.cpu.rdtsc,$execution.cpu.rdtscp,$execution.cpu.xgetbv)
                if(($actual -join ',') -ne ($expected -join ',')){throw 'Special CPU instruction bypassed guest model.'}
            }
            if($case.tsc_aux -and ($execution.cpu.rdtscp -ne 1 -or $execution.kernel_cpu.tracked_msr_write_observations -ne 1 -or @($execution.kernel_cpu.tracked_msrs | Where-Object {$_.index -eq 0xc0000103L -and $_.value -eq 0x55aa}).Count -ne 1)) {throw 'RDTSCP did not observe the guest-written TSC_AUX.'}
            if($case.msr_context -and ($execution.kernel_cpu.msr_context_repairs -ne 1 -or $execution.kernel_cpu.tracked_msr_write_observations -ne 1 -or @($execution.kernel_cpu.tracked_msrs | Where-Object {$_.index -eq 0xc0000082L -and $_.value -eq 0x12345678}).Count -ne 1)) {throw 'Thread context restore rewound processor MSR state.'}
            if ($case.kind -eq 'virtual-memory' -and ($execution.api_events[5].last_error -ne 487 -or $execution.api_events[6].result -ne 487)) { throw 'Bad release failure was not modeled.' }
            if ($case.kind -eq 'virtual-bad-protect-output' -and ($execution.api_events[1].result -ne 0 -or $execution.api_events[1].last_error -ne 998)) { throw 'Invalid protection output buffer was accepted.' }
            if ($case.modules -and $execution.loaded_modules.Count -ne $case.modules) {throw 'Companion module evidence is incomplete.'}
            if ($case.kernel -and ($execution.kernel_state.irql -ne 0 -or $execution.kernel_state.critical_depth -ne 0 -or $execution.kernel_state.owned_mutexes -ne 0)) {throw 'Kernel lock lifecycle left inconsistent state.'}
            if ($case.threads) {
                if($execution.kernel_threads.count -ne 2 -or $execution.kernel_threads.exited -ne 2 -or $execution.kernel_threads.switches -lt 2) {throw 'Guest system thread did not run to completion.'}
                $child=@($execution.kernel_threads.states | Where-Object {$_.slot -eq 2})
                if($child.Count -ne 1 -or $child[0].critical_depth -ne 1) {throw 'New system thread did not start in its documented critical region.'}
                if($case.kind -eq 'system-thread' -and ($execution.api_events[1].thread_id -ne 2 -or $execution.api_events[1].effect -ne 'terminates_current_thread' -or $null -ne $execution.api_events[1].result)) {throw 'Thread termination was incorrectly reported as a returned API.'}
            }
            if($case.handoff -and ($execution.kernel_threads.waits -ne 1 -or $execution.kernel_threads.resumed_waits -ne 1 -or $execution.api_events[3].effect -ne 'mutex_acquired' -or @($execution.api_events | Where-Object {$_.pending}).Count -ne 0)) {throw 'Mutex waiter did not resume exactly once.'}
            if ($case.file_failure -and $execution.api_events[$case.failure_index].last_error -ne $case.file_failure) {throw 'File API failure did not preserve its error.'}
            if ($case.file) {
                if ($execution.artifacts.Count -ne 1 -or $execution.artifacts[0].size -ne 4) {throw 'Guest file artifact was not captured.'}
                $artifact=$execution.artifacts[0]
                $artifactPath=Join-Path (Join-Path $run 'artifacts') $artifact.filename
                $bytes=[System.IO.File]::ReadAllBytes($artifactPath)
                if ([System.Text.Encoding]::ASCII.GetString($bytes) -ne 'RUST') {throw 'Guest artifact has wrong bytes.'}
                if ((Get-FileHash -LiteralPath $artifactPath).Hash.ToLowerInvariant() -ne $artifact.sha256) {throw 'Guest artifact hash mismatch.'}
                if ($artifact.observations[0].guest_path -ne 'c:\workspace\rust-fixture.bin') {throw 'Guest path metadata changed.'}
            }
        }
        $records += @{arch=$arch; case=$caseName; kind=$case.kind; exit_code=$exit; original_controller_exit_known=(-not $reused); completion=$execution.completion_reason; return=$execution.guest_entry_return; api_calls=$execution.api_calls; error=$execution.error; instructions=$execution.instruction_count; reused_generated_run=$reused}
        $records | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding UTF8
    }
}
$records | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding UTF8
Write-Output "Verified $($records.Count) isolated Rust API fixtures."
$global:LASTEXITCODE=0
