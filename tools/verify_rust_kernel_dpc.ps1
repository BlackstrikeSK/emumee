param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if((Test-Path -LiteralPath $root) -and -not $Resume){throw 'Preserve existing DPC invocation evidence; use explicit Resume.'}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'DPC frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "DPC frozen binary differs from receipt: $($binding.file)."}
}
if(-not (Test-Path -LiteralPath $root)){$null=New-Item -ItemType Directory -Path $root}
$cases=@(
 @{name='basic';started=1},@{name='duplicate';started=1;duplicates=1},@{name='fifo';started=2},@{name='remove';started=0;removed=1},
 @{name='elevated';started=1},@{name='callback-queue';started=2},@{name='timer';started=1;timer=$true},@{name='timer-wait';started=1;timer=$true},
 @{name='timer-read';started=1;timer=$true},@{name='timer-cancel';started=0},@{name='timer-replacement';started=0},@{name='periodic';started=1;timer=$true},
 @{name='void-context';started=1},@{name='root-fault';started=1;root=17;error='*INSN_INVALID*'},@{name='root-budget';started=1;root=17;budget=$true},
 @{name='running-requeue';started=1;error='*requeue of running DPC*'},@{name='wrong-return';started=1;error='*stack ABI*'},
 @{name='irql-return';started=1;error='*DPC*'},@{name='callback-fault';started=1;error='*INSN_INVALID*'},@{name='callback-budget';started=1;budget=$true},
 @{name='protect';started=0;error='*owned DPC environment*'},@{name='free';started=0;error='*owned DPC environment*'},@{name='recommit';started=0;error='*owned DPC environment*'},
 @{name='opaque-read';started=1;error='*READ_PROT*'},@{name='thread-parked';started=1;child=$true},
 @{name='due-dpc';legacy=$true;started=1;error='*EXCEPTION*'},@{name='dpc-read';legacy=$true;started=1;error='*EXCEPTION*'},@{name='dpc-wait';legacy=$true;started=1;error='*EXCEPTION*'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind=$(if($case.legacy){'kernel-timer-'}else{'kernel-dpc-'})+$case.name
 $negative=[bool]$case.error;$budgetCase=[bool]$case.budget;$positive=-not $negative -and -not $budgetCase
 $modes=@('full');if($positive){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -ceq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -ceq $arch -and $_.kind -ceq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'DPC actual instruction baseline missing.'};$budget=$baseline[0].instructions-1}elseif($budgetCase){$budget=2000}else{$budget=20000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  $reused=Test-Path -LiteralPath $run
  $consolePath=$run+'.console.log'
  if($reused){if(-not $Resume){throw 'Existing DPC run requires explicit Resume.'};$exit=$null}
  else{
   if(Test-Path -LiteralPath $consolePath){throw 'Orphaned DPC console evidence requires inspection; refusing overwrite.'}
   & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> $consolePath;$exit=$LASTEXITCODE
  }
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  if($reused){
   $savedConsole=Get-Content -LiteralPath $consolePath -Raw|ConvertFrom-Json
   if(($savedConsole|ConvertTo-Json -Depth 100 -Compress) -cne ($manifest|ConvertTo-Json -Depth 100 -Compress)){throw 'Saved DPC controller stdout differs from final manifest.'}
  }
  $requestPath=Join-Path $run 'request.json';$resultPath=Join-Path $run 'fixture-result.json'
  $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $expectedRequestKind=if($case.legacy){$kind -replace '^kernel-timer-','kernel-timers-'}else{$kind}
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($receipt.$key -cnotmatch '^[a-f0-9]{64}$' -or $manifest.$key -cne $receipt.$key){throw 'DPC run differs from frozen receipt.'}}
  if($manifest.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -cne $expectedRequestKind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000){throw 'DPC exact request/result/worker-exit/cleanup binding failed.'}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'DPC packaged offline containment failure.'}
  $e=$result.execution;$t=$e.kernel_threads;$d=$t.dpc
  if($e.backend -cne 'rust/unicorn-x86' -or $e.architecture -cne $arch -or $null -eq $e.kernel_cpu -or ($e.kernel_cpu.current.cs -band 3) -ne 0 -or $e.network.calls -ne 0 -or $e.api_events_omitted -ne 0 -or @($e.artifacts).Count -ne 0 -or @($e.kernel_ipi.rendezvous.broadcasts).Count -ne 0 -or $null -ne $e.configuration){throw "DPC actual guest-only backend/provenance mismatch: $arch $kind."}
  if($null -eq $t -or $null -eq $d -or $d.version -cne 'cpu0-dpc-dispatch-v1' -or -not $d.environment_prepared -or $d.policy.PSObject.Properties.Name -cnotcontains 'Cpu0Dispatch'){throw 'DPC normal engine failed to install genuine dispatch profile.'}
  $expectedThread=[UInt64]$e.kernel_entry.layout.root_thread
  if($expectedThread -eq 0){throw 'DPC authoritative initialized root Thread layout missing.'}
  $events=@($e.api_events);$ordinary=@($events|Where-Object {$_.execution_domain -ceq 'ordinary_thread' -and $_.thread_id -eq 1 -and $_.api -ceq 'ntoskrnl.PsGetCurrentThread'})
  if(-not $case.legacy){if($ordinary.Count -ne 1 -or $ordinary[0].result -eq 0){throw 'DPC actual root Thread observation missing.'};$expectedThread=[UInt64]$ordinary[0].result}
  if($arch -ceq 'x64' -and [UInt64]$d.layout.base -le [UInt64][UInt32]::MaxValue){throw 'DPC environment address truncated to32bits.'}
  if($t.count -ne $(if($case.child){2}else{1}) -or $d.omitted_invocations -ne 0 -or @($d.invocations).Count -ne [int]$case.started -or $d.counters.started -ne [int]$case.started){throw "DPC genuine invocation/thread count mismatch: $arch $kind."}
  foreach($invocation in @($d.invocations)){
   if($invocation.processor -ne 0 -or $invocation.thread_slot -ne 1 -or [UInt64]$invocation.thread -ne $expectedThread){throw 'DPC fabricated or changed interrupted processor/Thread identity.'}
   if($null -ne $invocation.return_instruction -and ($invocation.return_instruction -le $invocation.start_instruction -or -not $invocation.caller_restored)){throw 'DPC returned observation lacks genuine callback instructions/caller restoration.'}
   if($case.timer){if(@($invocation.work.arguments).Count -ne 2 -or [UInt64]$invocation.work.arguments[0] -ne [UInt64]$d.layout.timer_arguments[0] -or [UInt64]$invocation.work.arguments[1] -ne [UInt64]$d.layout.timer_arguments[1] -or $invocation.work.origin.PSObject.Properties.Name -cnotcontains 'Timer'){throw 'Timer DPC did not retain actual timer-origin opaque argument provenance.'}}
  }
  foreach($event in @($events|Where-Object {$_.execution_domain -ceq 'dpc'})){if($event.thread_id -ne 1 -or $event.processor -ne 0 -or [UInt64]$event.current_thread -ne $expectedThread -or $event.pending){throw 'DPC API changed actual Thread/CPU/domain or invented a blocking continuation.'}}
  if($case.root){if($t.root_entry_return -ne 17){throw 'Callback failure/budget lost actual prior root-return observation.'}}
  elseif($partial -or $negative -or $budgetCase){if($null -ne $t.root_entry_return){throw 'DPC incomplete caller fabricated root return.'}}
  elseif($t.root_entry_return -ne 17){throw 'DPC positive caller lost actual root return.'}
  if($case.legacy){if($d.counters.returned -ne 1 -or $d.counters.restored -ne 1 -or $d.active -or $t.timers[0].inserted -or -not $t.timers[0].signaled -or @($events|Where-Object {$_.error -or $_.pending}).Count){throw 'Literal legacy bad-marker callback did not truly execute/return/restore before guest assertion failure.'}}
  elseif($positive){
   if($d.counters.returned -ne [int]$case.started -or $d.counters.restored -ne [int]$case.started -or $d.active -or $d.native_effect_failure -or @($d.queued).Count -ne 0 -or $d.counters.duplicates -ne [int]$case.duplicates -or $d.counters.removed -ne [int]$case.removed){throw "DPC successful FIFO/lifetime/return restoration mismatch: $arch $kind."}
   if(@($events|Where-Object {$_.error -or $_.pending}).Count){throw 'DPC positive caller retained an error/pending continuation.'}
   if($case.child){
    $childWait=@($events|Where-Object {$_.thread_id -eq 2 -and $_.api -ceq 'ntoskrnl.KeWaitForSingleObject' -and -not $_.pending -and $_.result -eq 0 -and $_.effect -ceq 'event_signaled'})
    $signal=@($events|Where-Object {$_.execution_domain -ceq 'dpc' -and $_.api -ceq 'ntoskrnl.KeSetEvent'})
    $childExit=@($events|Where-Object {$_.thread_id -eq 2 -and $_.api -ceq 'ntoskrnl.PsTerminateSystemThread' -and $_.effect -ceq 'terminates_current_thread'})
    if($childWait.Count -ne 1 -or $signal.Count -ne 1 -or $childExit.Count -ne 1 -or $t.switches -lt 2 -or $t.waits -lt 1 -or $t.resumed_waits -lt 1){throw 'DPC child wait/signal/exit provenance missing.'}
    $waitIndex=[array]::IndexOf($events,$childWait[0]);$signalIndex=[array]::IndexOf($events,$signal[0]);$exitIndex=[array]::IndexOf($events,$childExit[0])
    if($waitIndex -lt 0 -or $signalIndex -le $waitIndex -or $exitIndex -le $signalIndex){throw 'DPC child wait must precede callback signal and genuine child exit.'}
   }
   $last=@($events|Where-Object {$_.thread_id -eq 1 -and $_.execution_domain -ceq 'ordinary_thread' -and $_.api -ceq 'kernel32.GetLastError'})[-1]
   if($last.result -ne 305419896L){throw 'DPC failed to restore actual ordinary caller LastError.'}
  }elseif([int]$case.started -eq 1){if(-not $d.active -or $d.counters.returned -ne 0 -or $d.counters.restored -ne 0 -or @($events|Where-Object {$_.execution_domain -ceq 'dpc' -and $_.api -ceq 'ntoskrnl.KeGetCurrentIrql' -and $_.result -eq 2}).Count -ne 1){throw 'Actual failed/budgeted DPC was not running at DISPATCH_LEVEL.'}}
  if($negative){if((-not $reused -and $exit -ne 1) -or $e.completion_reason -cne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "DPC actual failure mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial -or $budgetCase){if((-not $reused -and $exit -ne 1) -or $e.completion_reason -cne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'DPC exact shared budget prefix fabricated completion.'}}
  elseif((-not $reused -and $exit -ne 0) -or $e.completion_reason -cne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "DPC literal guest ABI/arguments/ordering/identity/poison/context assertions failed $arch ${kind}: $($e.error)"}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;dpc_profile=$d.version;started=$d.counters.started;returned=$d.counters.returned;restored=$d.counters.restored;root_entry_return=$t.root_entry_return;source_tree_sha256=$receipt.source_tree_sha256;request_sha256=$requestHash;result_sha256=$resultHash;reused_saved_run=$reused;original_controller_exit_known=(-not $reused);verified=$true}
  ConvertTo-Json -InputObject @($records) -Depth 8|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 84){throw 'DPC generated control count mismatch.'}
Write-Output "Verified $($records.Count) contained cpu0-dpc-dispatch-v1 actual callback/FIFO/arguments/identity/VOID/context/timer/wait/lifetime/budget/root-return controls."
$global:LASTEXITCODE=0
