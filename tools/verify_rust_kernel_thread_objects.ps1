param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing thread evidence; choose fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(
 @{name='lifecycle';calls=18},@{name='child-return';calls=17},@{name='close-after-exit';calls=18},
 @{name='invalid-handle';calls=19},@{name='closed-handle';calls=19},@{name='type-mismatch';calls=19},@{name='user-type-mismatch';calls=19},@{name='kernel-access';calls=18},
 @{name='user-mode';calls=9;early=$true;error='UserMode thread handle security'},@{name='readonly-output';calls=9;early=$true;error='lacks permission'},
 @{name='information-output';calls=9;early=$true;error='handle-information'},@{name='irql';calls=10;early=$true;error='PASSIVE_LEVEL'},
 @{name='foreign-handle';calls=9;early=$true;error='Foreign process/file'},
 @{name='released-wait';calls=19;error='released thread object'},@{name='released-reference';calls=19;error='live owned object body'},
 @{name='released-read';calls=18;error='private or released kernel thread body read|READ_PROT';denial=$true;retired=$true},
 @{name='root-header';calls=2;root=$true},@{name='root-private-cross';calls=1;root=$true;error='private or released kernel thread body read';denial=$true},
 @{name='root-previous-page-cross';calls=1;root=$true;error='private or released kernel thread body read';denial=$true},
 @{name='root-header-write';calls=1;root=$true;error='WRITE_PROT';denial=$true},
 @{name='root-terminate';calls=2;root=$true;error='outside a spawned system thread'},
 @{name='root-api-write';calls=2;root=$true;error='private or released kernel thread body access';denial=$true},
 @{name='header-read-benchmark';calls=1;root=$true;benchmark=$true},@{name='ordinary-read-benchmark';calls=1;root=$true;benchmark=$true}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-thread-objects-'+$case.name;$modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing actual-thread budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=if($case.benchmark){100000}else{1000}}
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
  $e=$result.execution;$r=$e.kernel_thread_objects;$objects=$e.kernel_objects
  if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Thread packaged offline containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $null -eq $r -or $e.api_calls -ne $case.calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or -not $r.read_guard_installed -or $r.native_effect_failure){throw "Thread native/offline/guard/API evidence mismatch $arch $kind."}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error){throw "Thread refusal mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Thread budget stop fabricated an entry return.'}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Actual guest thread lifecycle failed $arch ${kind}: $($e.error)"}
  $caller=@($r.threads|Where-Object {$_.slot -eq 1});if($caller.Count -ne 1 -or -not $caller[0].root_caller -or -not $caller[0].executing -or $caller[0].terminated -or $caller[0].retired -or $caller[0].open_handles -ne 0 -or $caller[0].owner -ne 4 -or $caller[0].address -ne $e.kernel_entry.layout.root_thread -or $e.kernel_cpu.pcr_current_thread -ne $caller[0].address){throw 'DriverEntry return consumed or contradicted its borrowed System caller.'}
  if($case.root){if(@($r.threads).Count -ne 1 -or @($r.handles).Count -ne 0){throw 'Root-only caller invented a child thread or handle.'};if($case.name -eq 'root-terminate' -and $null -ne $e.kernel_threads -and ($e.kernel_threads.exited -ne 0 -or $null -ne $e.kernel_threads.root_entry_return)){throw 'Rejected root termination changed scheduler lifetime.'}}
  else{
   $child=@($r.threads|Where-Object {$_.slot -eq 2});if($child.Count -ne 1 -or $child[0].root_caller -or $child[0].owner -ne 4){throw 'Child slot/owner identity is not genuine scheduler state.'}
   $body=@($objects.objects|Where-Object {$_.address -eq $child[0].address});if($body.Count -ne 1 -or $body[0].kind -ne 'Thread'){throw 'Scheduler and object-reference body identities differ.'}
   if($case.early){if(-not $child[0].executing -or $child[0].terminated -or $child[0].retired -or $child[0].open_handles -ne 1 -or @($r.handles).Count -ne 1 -or $body[0].api_references -ne 0 -or $body[0].permanent_references -ne 2 -or -not $body[0].live -or $e.kernel_threads.open_thread_handles -ne 1){throw 'Failed reference consumed a real handle/execution anchor or invented child exit.'}}
   elseif($child[0].executing -or -not $child[0].terminated -or -not $child[0].retired -or $child[0].open_handles -ne 0 -or @($r.handles).Count -ne 0 -or $body[0].api_references -ne 0 -or $body[0].permanent_references -ne 0 -or $body[0].live -or $e.kernel_threads.open_thread_handles -ne 0){throw 'Final thread ownership did not retire exactly after real exit/close/API release.'}
   foreach($handle in @($r.handles)){if($handle.slot -ne 2 -or $handle.object -ne $child[0].address -or $handle.owner -ne 4 -or -not $handle.kernel_only -or $handle.granted_access -ne 0x1fffff){throw 'Thread handle metadata was detached from actual creation.'}}
  }
  if($case.denial -and @($r.private_accesses|Where-Object {$_.retired -eq [bool]$case.retired}).Count -eq 0){throw 'Private/released thread memory lacked interval denial evidence.'}
  if(@($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.KeGetCurrentProcessorNumber' -and $_.result -ne 0}).Count){throw 'Thread slot was fabricated as logical CPU identity.'}
  if($case.name -eq 'kernel-access'){
   if(@($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.PsCreateSystemThread' -and $_.arguments[1] -eq 0}).Count -ne 1 -or @($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.ObReferenceObjectByHandle' -and $_.arguments[1] -eq 0x100000 -and $_.result -eq 0}).Count -ne 1){throw 'Legacy trusted KernelMode access behavior was silently changed.'}
  }
  if($case.benchmark -and $r.read_guard_checks -lt 10000){throw 'Owned repeat-read benchmark did not exercise the actual read guard.'}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;guard_reads=$r.read_guard_checks;engine_seconds=$e.engine_seconds;reused=[bool]$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 70){throw 'Actual thread control count mismatch.'}
$benchmarks=@();foreach($arch in @('x86','x64')){$header=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq 'kernel-thread-objects-header-read-benchmark' -and -not $_.partial})[0];$ordinary=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq 'kernel-thread-objects-ordinary-read-benchmark' -and -not $_.partial})[0];if($header.instructions -ne $ordinary.instructions){throw 'Read benchmark guest programs have unequal instruction counts.'};$benchmarks+=@{arch=$arch;instructions=$header.instructions;header_seconds=$header.engine_seconds;ordinary_seconds=$ordinary.engine_seconds;scope='Observed guarded header-range versus ordinary-address lookup cost for matched10000-read programs. Both use the guard; no unguarded baseline or speedup claim.'}}
$benchmarks|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'benchmark-observations.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained actual-thread handle/lifetime/continuation/interval/budget controls and recorded read-guard timings."
$global:LASTEXITCODE=0
