param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing thread evidence; choose fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(
 @{name='delay-relative';calls=5;delay=$true},@{name='delay-absolute';calls=6;delay=$true},@{name='delay-zero';calls=5},@{name='delay-child';calls=8;delay=$true;child=$true},
 @{name='delay-mode';calls=5;error='Alertable/UserMode kernel delay'},@{name='delay-alertable';calls=5;error='Alertable/UserMode kernel delay'},
 @{name='delay-irql';calls=6;error='delay above APC_LEVEL'},@{name='delay-unreadable';calls=5;error='System-thread argument range is not accessible'},
 @{name='any';calls=5},@{name='all';calls=5},@{name='all-blocked';calls=9;child=$true;joined=$true},@{name='mixed';calls=9;child=$true;joined=$true},
 @{name='timeout';calls=5;timeout=$true},@{name='poll';calls=5},@{name='four';calls=5},
 @{name='count-zero';calls=5;error='Invalid multiple kernel wait count/type'},@{name='count65';calls=5;error='Invalid multiple kernel wait count/type'},
 @{name='type';calls=5;error='Invalid multiple kernel wait count/type'},@{name='duplicate';calls=5;error='Duplicate dispatcher objects'},
 @{name='user-mode';calls=5;error='Alertable/UserMode multiple kernel wait'},@{name='alertable';calls=5;error='Alertable/UserMode multiple kernel wait'},
 @{name='missing-blocks';calls=5;error='wait-block storage'},@{name='readonly-blocks';calls=5;error='System-thread argument range is not accessible'},
 @{name='bad-array';calls=5;error='System-thread argument range is not accessible'},@{name='unknown';calls=5;error='unknown event'},
 @{name='irql';calls=6;error='blocking wait above APC_LEVEL'},@{name='tamper';calls=5;error='Guest event state diverges from scheduler'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-waits-'+$case.name;$modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing kernel-wait budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=10000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}));$reused=Test-Path -LiteralPath $run
  if($reused){if(-not $Resume){throw 'Never overwrite an existing generated thread run.'}}
  else{& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultPath=Join-Path $run 'fixture-result.json';$resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Thread run belongs to another frozen build.'}}
  if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -ne $kind -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget){throw 'Thread request/result/build/cleanup binding failed.'}
  $e=$result.execution;$t=$e.kernel_threads;$r=$e.kernel_thread_objects
  if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Kernel wait packaged offline containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $null -eq $t -or $null -eq $r -or $e.api_calls -ne $case.calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or $t.native_wait_effect_failure -or $r.native_effect_failure){throw "Kernel wait native/offline/API/state mismatch $arch $kind."}
  $caller=@($r.threads|Where-Object {$_.slot -eq 1});if($caller.Count -ne 1 -or -not $caller[0].root_caller -or -not $caller[0].executing -or $caller[0].terminated -or $caller[0].retired -or $caller[0].address -ne $e.kernel_entry.layout.root_thread){throw 'Kernel wait consumed borrowed System caller ownership.'}
  if($case.error){
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error -or $t.exited -ne 0 -or $t.waits -ne 0 -or $t.resumed_waits -ne 0){throw "Kernel wait refusal changed state or missed its contract $arch ${kind}: $($e.error)"}
  }elseif($partial){
   if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Kernel wait budget stop fabricated a return.'}
  }elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Kernel wait actual guest checks failed $arch ${kind}: $($e.error)"}
  if(-not $case.error){
   if($case.delay -and @($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.KeDelayExecutionThread' -and $_.result -eq 0 -and $_.effect -eq 'delay_elapsed' -and -not $_.pending}).Count -ne 1){throw 'Delay had no actual deadline continuation completion.'}
   if($case.joined -and @($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.KeWaitForMultipleObjects' -and $_.result -eq 0 -and $_.effect -eq 'multiple_wait_satisfied' -and -not $_.pending}).Count -ne 1){throw 'Blocked wait-all had no actual object satisfaction continuation.'}
   if($case.timeout -and @($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.KeWaitForMultipleObjects' -and $_.result -eq 258 -and $_.effect -eq 'wait_timeout' -and -not $_.pending}).Count -ne 1){throw 'Wait timeout had no actual deadline wake.'}
   $expected=if($case.child){2}else{1}
   if($t.count -ne $expected -or $t.exited -ne ($expected-[int]$partial) -or $t.open_thread_handles -ne 0 -or @($r.handles).Count -ne 0){throw 'Kernel wait scheduler/handle lifetime report differs from executed guest tasks.'}
   if($case.child){$child=@($r.threads|Where-Object {$_.slot -eq 2});if($child.Count -ne 1 -or -not $child[0].terminated -or -not $child[0].retired -or $child[0].executing -or $child[0].open_handles -ne 0){throw 'Kernel wait fabricated or leaked child termination.'}}
  }
  foreach($event in @($e.api_events|Where-Object {$_.pending})){if($null -ne $event.result){throw 'Pending kernel wait invented its status.'}}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;waits=$t.waits;resumed=$t.resumed_waits;reused=[bool]$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 76){throw 'Kernel wait control count mismatch.'}
Write-Output "Verified $($records.Count) contained delay/multiple wait-all/any/thread/deadline/mirror/refusal/budget controls."
$global:LASTEXITCODE=0
