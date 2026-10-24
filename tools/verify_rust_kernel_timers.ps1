param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if((Test-Path -LiteralPath $root) -and -not $Resume){throw 'Preserve existing timer/DPC evidence; use explicit Resume.'}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'Timer frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "Timer frozen binary differs from receipt: $($binding.file)."}
}
if(-not(Test-Path -LiteralPath $root)){$null=New-Item -ItemType Directory -Path $root}
$cases=@(
 @{name='initialize';init=2;dpc=1},@{name='relative';signal=$true},@{name='synchronization'},
 @{name='absolute-past';signal=$true},@{name='absolute-future';signal=$true;absolute=$true},
 @{name='large-due';large=$true},@{name='replacement'},@{name='periodic';signal=$true;period=1},
 @{name='polling';signal=$true},@{name='mixed-any';init=2;signal=$true},@{name='mixed-all'},
 @{name='child';child=$true;signal=$true},@{name='dpc-cancel';dpc=1},
 @{name='pool-lifetime';init=2;retired=$true;allocs=2;frees=2},
 @{name='due-dpc';dpc=1;inserted=$true;error='*due timer DPC requires callback scheduling*'},
 @{name='pending-dpc';dpc=1;inserted=$true;root=17;outside=$true;error='*Inserted timer DPC requires callback scheduling*'},
 @{name='dpc-read';dpc=1;inserted=$true;outside=$true;stop=$true;error='*due timer DPC requires callback scheduling*'},
 @{name='dpc-wait';dpc=1;inserted=$true;outside=$true;pending=$true;error='*due timer DPC requires callback scheduling*'},
 @{name='reinitialize';inserted=$true;error='*reinitializing inserted/waited timer*'},
 @{name='negative-period';error='*negative timer period*'},@{name='unknown-dpc';error='*uninitialized timer DPC*'},
 @{name='readonly';none=$true;error='*API guest range*'},@{name='paged';none=$true;allocs=1;error='*cannot be paged Pool*'},
 @{name='direct-write';uncertain=$true;stop=$true;outside=$true;error='*Direct guest mutation of initialized timer/DPC metadata*'},
 @{name='api-write';error='*API mutation of initialized timer/DPC metadata*'},
 @{name='inserted-free';inserted=$true;allocs=1;error='*memory release overlaps inserted/waited timer*'},
 @{name='alias-after';error='*MDL alias/descriptor overlaps initialized timer/DPC metadata*'},
 @{name='high-irql';irql=3;error='*at or below DISPATCH_LEVEL*'},
 @{name='dpc-routine';none=$true;error='*actual executable guest image provenance*'},
 @{name='budget-pending';budget=$true;dpc=1;inserted=$true}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-timer-'+$case.name;$requestKind='kernel-timers-'+$case.name;$negative=[bool]$case.error;$budgetCase=[bool]$case.budget
 $modes=@('full');if(-not $negative -and -not $budgetCase){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -ceq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -ceq $arch -and $_.kind -ceq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Timer actual instruction baseline missing.'};$budget=$baseline[0].instructions-1}elseif($budgetCase){$budget=2000}else{$budget=20000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  $reused=Test-Path -LiteralPath $run
  if($reused){if(-not $Resume){throw 'Existing timer run requires explicit Resume.'};$exit=$null}
  else{& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  if($reused){$savedConsole=Get-Content -LiteralPath ($run+'.console.log') -Raw|ConvertFrom-Json;if(($savedConsole|ConvertTo-Json -Depth 100 -Compress) -cne ($manifest|ConvertTo-Json -Depth 100 -Compress)){throw 'Saved timer controller stdout differs from final manifest.'}}
  $requestPath=Join-Path $run 'request.json';$resultPath=Join-Path $run 'fixture-result.json'
  $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($receipt.$key -cnotmatch '^[a-f0-9]{64}$' -or $manifest.$key -cne $receipt.$key){throw 'Timer run differs from frozen build receipt.'}}
  if($manifest.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -cne $requestKind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000){throw 'Timer exact request/result/worker-exit/cleanup binding failed.'}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Timer packaged offline containment failure.'}
  $e=$result.execution;$t=$e.kernel_threads;$pool=$e.kernel_pool
  if($e.backend -cne 'rust/unicorn-x86' -or $e.architecture -cne $arch -or $null -eq $pool -or $null -eq $e.kernel_cpu -or ($e.kernel_cpu.current.cs -band 3) -ne 0 -or $null -ne $e.console -or $null -ne $e.crt_stdio -or $null -ne $e.configuration -or $e.network.calls -ne 0 -or $e.api_events_omitted -ne 0 -or @($e.artifacts).Count -ne 0 -or @($e.kernel_ipi.rendezvous.broadcasts).Count -ne 0){throw "Timer actual guest-only backend/provenance mismatch: $arch $kind."}
  if($e.kernel_state.irql -ne [int]$case.irql -or $e.kernel_state.critical_depth -ne 0 -or $e.kernel_state.owned_mutexes -ne 0 -or $e.kernel_state.spin.initializations -ne 0){throw "Timer changed unrelated IRQL/critical/spin state: $arch $kind."}
  if($pool.total_allocations -ne [int]$case.allocs -or $pool.total_frees -ne [int]$case.frees -or @($pool.allocations.PSObject.Properties).Count -ne ([int]$case.allocs-[int]$case.frees)){throw "Timer real Pool allocation/free count mismatch: $arch $kind."}
  if($arch -ceq 'x64' -and @($pool.allocations.PSObject.Properties|Where-Object {[UInt64]$_.Value.base -le [UInt64][UInt32]::MaxValue}).Count){throw 'Timer Pool pointer was truncated to32bits.'}
  if([bool]$case.none){if($null -ne $t){throw "Failed timer initialization published scheduler/metadata: $arch $kind."}}
  else{
   $initializations=if($case.init){[int]$case.init}else{1};$timerCount=if([bool]$case.retired){0}else{$initializations};$threadCount=if([bool]$case.child){2}else{1}
   if($null -eq $t -or $t.count -ne $threadCount -or $t.native_wait_effect_failure -or [bool]$t.timer_native_effect_failure -ne [bool]$case.uncertain -or -not $t.timer_guards_installed -or $t.timer_guest_denials -ne [int]([bool]$case.uncertain) -or ($null -ne $t.timer_stop) -ne [bool]$case.stop){throw "Timer real scheduler/native-effect/guard state mismatch: $arch $kind."}
   if($t.timer_initializations -ne $initializations -or @($t.timers).Count -ne $timerCount -or $t.dpc_initializations -ne [int]$case.dpc -or @($t.dpcs_initialized).Count -ne [int]$case.dpc){throw "Timer catalog/lifetime initialization mismatch: $arch $kind."}
   foreach($timer in @($t.timers)){
    if($timer.architecture -cne $arch -or [bool]$timer.inserted -ne [bool]$case.inserted -or [bool]$timer.signaled -ne [bool]$case.signal -or $timer.period_ms -ne [int]$case.period){throw "Timer actual armed/signal/period state mismatch: $arch $kind."}
    if([bool]$case.period -and $timer.due -le $e.virtual_uptime_ms*10000){throw 'Periodic timer failed to coalesce to a future deadline.'}
    if([bool]$case.large -and $timer.due -le 523812000L*10000+4294967296L){throw 'Timer x86 by-value64 DueTime was truncated.'}
    if([bool]$case.absolute -and ($timer.due -ne 523812000L*10000+100000 -or $e.virtual_uptime_ms -lt 523812010)){throw 'Absolute timer did not use the coherent UTC/interrupt clock authority.'}
    if($case.name -cin @('due-dpc','dpc-read','dpc-wait') -and $timer.dpc -eq 0){throw 'Due callback refusal discarded genuine inserted DPC metadata.'}
    if($case.name -cin @('due-dpc','dpc-read','dpc-wait') -and $timer.due -ge ($e.virtual_uptime_ms+1)*10000){throw 'Due callback refusal happened before its real guest deadline.'}
    if($case.name -cin @('pending-dpc','budget-pending') -and $timer.due -le $e.virtual_uptime_ms*10000){throw 'Future pending callback metadata lost its real future deadline.'}
   }
   foreach($dpc in @($t.dpcs_initialized)){if($dpc.architecture -cne $arch -or $dpc.routine -eq 0 -or $dpc.context -eq 0 -or ($arch -ceq 'x64' -and ([UInt64]$dpc.routine -le [UInt64][UInt32]::MaxValue -or [UInt64]$dpc.context -le [UInt64][UInt32]::MaxValue))){throw 'Initialized DPC routine/context lost real full-width provenance.'}}
   if([bool]$case.child -and ($t.switches -lt 2 -or $t.waits -lt 2 -or $t.resumed_waits -lt 2)){throw 'Timer child/root continuations were not genuinely blocked/resumed.'}
   if($case.root){if($t.root_entry_return -ne [int]$case.root){throw 'Pending-DPC lifecycle error lost actual observed root return.'}}
   elseif($partial -or $negative -or $budgetCase){if($null -ne $t.root_entry_return){throw 'Incomplete timer caller fabricated root-return observation.'}}
   elseif($t.root_entry_return -ne 17){throw 'Successful timer caller lost actual root-return observation.'}
  }
  $events=@($e.api_events)
  foreach($event in $events){
   $lastError=if($event.thread_id -eq 1){305419896L}else{2271560481L}
   if($event.thread_id -notin @(1,2) -or $event.execution_domain -cne 'ordinary_thread' -or $event.last_error -ne $lastError -or ($event.api -notlike 'ntoskrnl.*' -and $event.api -notlike 'kernel32.*')){throw "Timer changed actual LastError/context/provider: $arch $kind."}
   if($event.api -cin @('ntoskrnl.KeInitializeTimer','ntoskrnl.KeInitializeTimerEx','ntoskrnl.KeInitializeDpc') -and $null -ne $event.result){throw 'Timer/DPC void initialization fabricated a return value.'}
  }
  if([bool]$case.pending){if(@($events|Where-Object {$_.pending -and $_.api -ceq 'ntoskrnl.KeWaitForSingleObject' -and $null -eq $_.result}).Count -ne 1){throw 'Due-DPC scheduler refusal fabricated a completed timer wait.'}}
  elseif(@($events|Where-Object {$_.pending}).Count){throw 'Timer caller retained an unexpected pending API continuation.'}
  if([bool]$case.child -and @($events|Where-Object {$_.thread_id -eq 2 -and $_.api -ceq 'ntoskrnl.PsTerminateSystemThread'}).Count -ne 1){throw 'Timer child did not genuinely reach system-thread termination.'}
  if($negative){
   if((-not $reused -and $exit -ne 1) -or $e.completion_reason -cne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "Timer honest refusal mismatch $arch ${kind}: $($e.error)"}
   if([bool]$case.outside){if(@($events|Where-Object {$null -ne $_.error}).Count){throw 'Timer read/scheduler/completion refusal was falsely attached to a completed API.'}}elseif($null -eq $events[-1].error){throw 'Timer failed API observation is missing.'}
  }elseif($partial -or $budgetCase){
   if((-not $reused -and $exit -ne 1) -or $e.completion_reason -cne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "Timer exact budget prefix fabricated completion: $arch $kind."}
  }elseif((-not $reused -and $exit -ne 0) -or $e.completion_reason -cne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Timer literal bytes/header/poison/ABI/LastError assertions failed $arch ${kind}: $($e.error)"}
  if(-not $negative){if(@($events|Where-Object {$null -ne $_.error}).Count){throw 'Timer positive/budget caller fabricated an API error.'}if(-not $budgetCase -and ($events[-1].api -cne 'kernel32.GetLastError' -or $events[-1].result -ne 305419896L -or $events[-1].thread_id -ne 1)){throw 'Timer positive caller did not preserve actual root GetLastError result.'}}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;timer_initializations=$(if($null -ne $t){$t.timer_initializations}else{0});dpc_initializations=$(if($null -ne $t){$t.dpc_initializations}else{0});root_entry_return=$(if($null -ne $t){$t.root_entry_return}else{$null});source_tree_sha256=$receipt.source_tree_sha256;request_sha256=$requestHash;result_sha256=$resultHash;reused_saved_run=$reused;original_controller_exit_known=(-not $reused);verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 88){throw 'Timer control count mismatch.'}
Write-Output "Verified $($records.Count) contained timer/layout/clock/AnyAll/polling/lifetime/ABI/DPC-refusal/root-return/budget controls."
$global:LASTEXITCODE=0
