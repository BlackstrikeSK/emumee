param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if((Test-Path -LiteralPath $root) -and -not $Resume){throw 'Preserve existing spin/preemption evidence; use explicit Resume.'}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'Spin frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "Spin frozen binary differs from receipt: $($binding.file)."}
}
if(-not(Test-Path -LiteralPath $root)){$null=New-Item -ItemType Directory -Path $root}
# Initializations, completed transitions, held live records, observed actual IRQL.
# These are observations expected from the literal generated callers, not an
# instruction to repair guest state or overwrite any run artifact.
$cases=@(
 @{name='basic';init=1;steps=3},@{name='nested';init=2;steps=6},@{name='old-apc';init=1;steps=3},
 @{name='critical';init=1;steps=3},@{name='pool';init=1;steps=3;allocs=1;frees=1;retired=$true},
 @{name='reused-pool';init=2;steps=6;allocs=2;frees=2;retired=$true},
 @{name='scheduler';init=1;steps=3;scheduler=$true},@{name='native-quantum';scheduler=$true},
 @{name='apc-quantum';scheduler=$true;apc=$true},@{name='ipi-restored';init=1;steps=3;ipi=$true},
 @{name='recursive';init=1;steps=2;held=1;irql=2;error='*busy or recursive spin acquisition*'},
 @{name='release-unowned';init=1;steps=1;error='*release without a spin owner*'},
 @{name='saved-irql';init=1;steps=2;held=1;irql=2;error='*saved/current IRQL mismatch*'},
 @{name='out-of-order';init=2;steps=4;held=2;irql=2;error='*out-of-order spin release*'},
 @{name='held-exit';init=1;steps=2;held=1;irql=2;error='*thread exit while owning a spin lock*';outside=$true},
 @{name='held-free';init=1;steps=2;held=1;irql=2;allocs=1;error='*memory release overlaps a held spin lock*'},
 @{name='lower-held';init=1;steps=2;held=1;irql=2;error='*owner lowered below DISPATCH_LEVEL*'},
 @{name='direct-lower-held';init=1;steps=2;held=1;error='*owner lowered below DISPATCH_LEVEL*'},
 @{name='direct-write';init=1;steps=2;held=1;irql=2;error='*Direct guest mutation of an initialized spin word*';outside=$true;uncertain=$true},
 @{name='api-write';init=1;steps=1;error='*API mutation of an initialized spin word*'},
 @{name='readonly';error='*API guest range*'},@{name='unaligned';error='*null or unaligned word*'},
 @{name='invalid-range';error='*API guest range*'},@{name='paged';allocs=1;error='*Spin backing cannot be paged Pool*'},
 @{name='unsupported-backing';error='*outside initialized guest-image/nonpaged-Pool profile*'},
 @{name='alias-first';allocs=2;snapshots=2;error='*unsupported MDL alias*'},
 @{name='alias-after';init=1;steps=1;allocs=1;error='*MDL alias/descriptor overlaps an initialized spin word*'},
 @{name='literal-alias';error='*Unsupported Windows API*'},
 @{name='high-irql';init=1;steps=1;irql=3;error='*acquisition above DISPATCH_LEVEL*'},
 @{name='ipi-while-held';init=1;steps=2;held=1;irql=2;error='*IPI entry while holding a spin lock*'},
 @{name='reuse-uninitialized';init=1;steps=3;allocs=2;frees=1;retired=$true;error='*uninitialized or retired spin lock*'},
 @{name='native-budget';scheduler=$true;budget=$true;irql=2},
 @{name='held-budget';scheduler=$true;budget=$true;init=1;steps=2;held=1;irql=2}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-spin-'+$case.name;$negative=[bool]$case.error;$budgetCase=[bool]$case.budget
 $modes=@('full');if(-not $negative -and -not $budgetCase){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -ceq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -ceq $arch -and $_.kind -ceq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Spin actual instruction baseline missing.'};$budget=$baseline[0].instructions-1}elseif($budgetCase){$budget=2000}else{$budget=20000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  $reused=Test-Path -LiteralPath $run
  if($reused){
   if(-not $Resume){throw 'Existing spin evidence requires explicit Resume.'}
   $savedConsole=Get-Content -LiteralPath ($run+'.console.log') -Raw|ConvertFrom-Json
   $exit=$null
  }else{
   & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE
  }
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  if($reused -and (($savedConsole|ConvertTo-Json -Depth 100 -Compress) -cne ($manifest|ConvertTo-Json -Depth 100 -Compress))){throw 'Saved controller stdout differs from final manifest.'}
  $requestPath=Join-Path $run 'request.json';$resultPath=Join-Path $run 'fixture-result.json'
  $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($receipt.$key -cnotmatch '^[a-f0-9]{64}$' -or $manifest.$key -cne $receipt.$key){throw 'Spin run differs from frozen build receipt.'}}
  if($manifest.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -cne $kind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000){throw 'Spin exact request/result/worker-exit/cleanup binding failed.'}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Spin packaged offline containment failure.'}
  $e=$result.execution;$k=$e.kernel_state;$s=$k.spin;$pool=$e.kernel_pool;$ipi=$e.kernel_ipi
  if($e.backend -cne 'rust/unicorn-x86' -or $e.architecture -cne $arch -or $null -eq $k -or $null -eq $pool -or $null -eq $ipi -or $null -eq $e.kernel_cpu -or ($e.kernel_cpu.current.cs -band 3) -ne 0 -or $null -ne $e.console -or $null -ne $e.crt_stdio -or $null -ne $e.configuration -or $e.network.calls -ne 0 -or $e.api_events_omitted -ne 0){throw 'Spin actual guest-only backend/kernel provenance mismatch.'}
  $spinRecords=@($s.records.PSObject.Properties|ForEach-Object {$_.Value});$held=@($spinRecords|Where-Object {$_.live -and $null -ne $_.held})
  if($s.initializations -ne [int]$case.init -or $s.transitions -ne [int]$case.steps -or $held.Count -ne [int]$case.held -or $k.irql -ne [int]$case.irql -or $k.critical_depth -ne 0 -or $k.owned_mutexes -ne 0){throw "Spin actual transitions/owner/IRQL mismatch: $arch $kind."}
  if([bool]$s.native_effect_failure -ne [bool]$case.uncertain -or $k.spin_guest_denials -ne [int]([bool]$case.uncertain) -or [bool]$k.spin_guard_installed -ne ([int]$case.init -gt 0)){throw 'Spin guest-write/native-effect accounting mismatch.'}
  $width=if($arch -ceq 'x64'){8}else{4}
  $rootThread=if($arch -ceq 'x64'){[UInt64]::Parse('ffffa10000002000',[Globalization.NumberStyles]::HexNumber)}else{[UInt64]3489669120}
  foreach($record in $spinRecords){
   if($record.width -ne $width -or ([UInt64]$record.address % $width) -ne 0 -or $record.initialization -le 0 -or $record.initialization -gt $s.initializations){throw 'Spin backing/initialization provenance mismatch.'}
   if($null -ne $record.held -and ($record.held.owner.processor -ne 0 -or [UInt64]$record.held.owner.thread -ne $rootThread)){throw 'Spin owner did not resolve actual root processor/thread authority.'}
  }
  if([int]$case.init -eq 0){if($null -ne $s.last_attempt -or $spinRecords.Count -ne 0){throw 'Failed initialization fabricated a transition/record.'}}elseif(-not $s.last_attempt.completed){throw 'Spin last successful API transition lost completion evidence.'}
  if([bool]$case.retired -and @($spinRecords|Where-Object {$_.live}).Count){throw 'Freed Pool retained live initialized spin identity.'}
  if($pool.total_allocations -ne [int]$case.allocs -or $pool.total_frees -ne [int]$case.frees -or @($pool.allocations.PSObject.Properties).Count -ne ([int]$case.allocs-[int]$case.frees)){throw 'Spin genuine Pool allocation/free/retirement count mismatch.'}
  if($arch -ceq 'x64' -and [int]$case.allocs -gt 0 -and @($pool.allocations.PSObject.Properties|Where-Object {[UInt64]$_.Value.base -le [UInt64][UInt32]::MaxValue}).Count){throw 'Spin Pool pointer was truncated to32bits.'}
  if(@($e.artifacts).Count -ne [int]$case.snapshots){throw 'Spin artifact capture count mismatch.'}
  foreach($artifact in @($e.artifacts)){foreach($observation in @($artifact.observations)){if($observation.kind -cne 'memory_snapshot' -or $observation.source -notlike 'kernel_mdl_*'){throw 'Spin MDL capture mislabeled as another artifact family.'}}}
  if([bool]$case.ipi){if(@($ipi.rendezvous.broadcasts).Count -ne 1 -or -not $ipi.rendezvous.broadcasts[0].completed -or $ipi.rendezvous.broadcasts[0].source_result -ne 0xbeef -or $ipi.current_processor -ne 0){throw 'Spin release/IPI source result/restoration mismatch.'}}elseif(@($ipi.rendezvous.broadcasts).Count){throw 'Refused spin/IPI boundary fabricated a broadcast.'}
  $events=@($e.api_events)
  foreach($event in $events){
   $expectedError=if($event.thread_id -eq 1){0x12345678}else{0x87654321L}
   if($event.thread_id -notin @(1,2) -or $event.execution_domain -cne 'ordinary_thread' -or $event.last_error -ne $expectedError -or $event.pending -or ($event.api -notlike 'ntoskrnl.*' -and $event.api -notlike 'kernel32.*')){throw 'Spin changed actual caller LastError/context/provider contract.'}
   if($event.api -like '*.KeInitializeSpinLock' -or $event.api -like '*.KeReleaseSpinLock' -or $event.api -like '*.KfReleaseSpinLock'){if($null -ne $event.result){throw 'Spin void routine fabricated a result.'}}
  }
  if([bool]$case.scheduler){
   $t=$e.kernel_threads
   if($null -eq $t -or $t.count -ne 2 -or $t.native_wait_effect_failure){throw 'Spin ordinary-thread provenance mismatch.'}
   if([bool]$case.apc){if($t.suppressed_quanta -ne 0){throw 'APC_LEVEL incorrectly suppressed ordinary quantum.'}}elseif($t.suppressed_quanta -le 0){throw 'Actual high IRQL did not suppress a due ordinary quantum.'}
   if($budgetCase){if($t.switches -ne 0 -or $t.exited -ne 0 -or $null -ne $t.root_entry_return -or @($events|Where-Object {$_.thread_id -ne 1}).Count){throw 'High-IRQL budget prefix fabricated child execution/return.'}}
   elseif($t.switches -le 0 -or @($events|Where-Object {$_.thread_id -eq 2 -and $_.api -like '*.PsTerminateSystemThread'}).Count -ne 1){throw 'Child failed to resume/terminate after actual IRQL allowed scheduling.'}
  }
  if($negative){
   if((-not $reused -and $exit -ne 1) -or $e.completion_reason -cne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "Spin honest refusal mismatch $arch ${kind}: $($e.error)"}
   if([bool]$case.outside){if(@($events|Where-Object {$null -ne $_.error}).Count){throw 'Native-write/exit refusal was falsely attached to a completed API.'}}elseif($null -eq $events[-1].error){throw 'Spin actual failed API observation missing.'}
  }elseif($partial -or $budgetCase){
   if((-not $reused -and $exit -ne 1) -or $e.completion_reason -cne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Spin exact prefix fabricated completion.'}
  }elseif((-not $reused -and $exit -ne 0) -or $e.completion_reason -cne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Spin actual bytes/poison/ABI/LastError assertions failed $arch ${kind}: $($e.error)"}
  if(-not $negative -and -not $budgetCase){if(@($events|Where-Object {$null -ne $_.error}).Count -or $events[-1].api -notlike '*.GetLastError' -or $events[-1].result -ne 0x12345678 -or $events[-1].thread_id -ne 1){throw 'Spin successful caller last-error/result observation mismatch.'}}
  $records+=@{reused_saved_run=$reused;original_controller_exit_known=(-not $reused);arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;initializations=$s.initializations;transitions=$s.transitions;held=$held.Count;irql=$k.irql;suppressed_quanta=$(if($null -ne $e.kernel_threads){$e.kernel_threads.suppressed_quanta}else{0});source_tree_sha256=$receipt.source_tree_sha256;request_sha256=$requestHash;result_sha256=$resultHash;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 86){throw 'Spin control count mismatch.'}
Write-Output "Verified $($records.Count) contained genuine-spin/owner/IRQL/preemption/ABI/lifetime/alias/IPI/refusal/budget controls."
$global:LASTEXITCODE=0
