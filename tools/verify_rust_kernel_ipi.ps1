param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing thread evidence; choose fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(
 @{name='basic';logical=12;calls=41},@{name='one';logical=1;calls=8},@{name='four';logical=4;calls=17},@{name='twelve';logical=12;calls=41},
 @{name='group-boundary';logical=64;calls=197},@{name='barrier';logical=12;calls=41},@{name='repeat';logical=12;calls=78;repeat=$true},
 @{name='wide';logical=12;calls=41},@{name='background';logical=12;calls=51;child=$true},@{name='child-caller';logical=12;calls=48;child=$true},
 @{name='msr-isolation';logical=12;calls=78;repeat=$true;msr=$true},
 @{name='fault';logical=12;calls=8;error='INSN_INVALID|EXCEPTION'},@{name='invalid';logical=12;calls=2;error='not executable guest code';no_group=$true},
 @{name='nested';logical=12;calls=6;error='nested broadcast'},@{name='terminate';logical=12;calls=6;error='IPI callback cannot terminate'},
 @{name='irql';logical=12;calls=5;error='corrupted current-thread/IRQL|corrupted CR8/GS'},@{name='budget';logical=12;calls=8;budget_stop=$true},
 @{name='high-irql';logical=12;calls=3;error='below IPI_LEVEL';no_group=$true},@{name='marker';logical=12;calls=2;error='return marker';no_group=$true},
 @{name='control-mutation';logical=12;calls=5;error='non-MSR processor control mutation'},@{name='descriptor-mutation';logical=12;calls=5;error='descriptor mutation'},@{name='unowned-msr';logical=12;calls=5;error='MSR ownership is not modeled'},
 @{name='lower-wait';logical=12;calls=11;error='IPI member API entry requires actual IPI_LEVEL';lowered=$true}, @{name='lower-delay';logical=12;calls=11;error='IPI member API entry requires actual IPI_LEVEL';lowered=$true}, @{name='lower-mutex';logical=12;calls=12;error='IPI member API entry requires actual IPI_LEVEL';lowered=$true}, @{name='lower-create';logical=12;calls=11;error='IPI member API entry requires actual IPI_LEVEL';lowered=$true},
 @{name='pcr-irql';logical=12;calls=5;error='corrupted current-thread/IRQL|requires actual IPI_LEVEL'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-ipi-'+$case.name;$groupRefusal=$case.name -eq 'group-boundary' -and $arch -eq 'x86';$negative=[bool]($case.error -or $case.budget_stop -or $groupRefusal);$calls=if($groupRefusal){2}else{$case.calls};$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing kernel-wait budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=if($case.budget_stop){512}else{100000}}
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
  $e=$result.execution;$r=$e.kernel_ipi;$owned=$e.kernel_thread_objects;$objects=$e.kernel_objects
  if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'IPI packaged offline containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $null -eq $r -or $null -eq $owned -or $e.api_calls -ne $calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or $e.kernel_environment.identity.logical_processors -ne $case.logical){throw "IPI actual native/profile/API report mismatch $arch $kind."}
  $caller=@($owned.threads|Where-Object {$_.root_caller});if($caller.Count -ne 1 -or $caller[0].role -ne 'InitialCaller' -or -not $caller[0].executing -or $caller[0].terminated -or $caller[0].retired -or $caller[0].address -ne $e.kernel_entry.layout.root_thread){throw 'IPI consumed borrowed System caller ownership.'}
  $groups=@($r.rendezvous.broadcasts)
  if($negative){
   if($exit -ne 1 -or $null -ne $e.guest_entry_return){throw 'Failed IPI invented a driver entry return.'}
   if($case.budget_stop){if($e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne 512 -or $null -ne $e.error -or $groups.Count -ne 1 -or @($groups[0].members|Where-Object {$_.started -and $_.instruction_count -gt 0}).Count -eq 0){throw 'IPI did not share its actual global instruction budget.'}}
   else{$expected=if($groupRefusal){'one bounded configured processor group'}else{$case.error};if($e.completion_reason -ne 'error' -or $e.error -notmatch $expected){throw "IPI negative profile missed real failure $arch ${kind}: $($e.error)"}}
   if($case.no_group -or $groupRefusal){if($groups.Count -ne 0 -or @($objects.objects).Count -ne 3){throw 'Rejected IPI allocated parked objects or claimed callbacks.'}}
   foreach($group in $groups){if($group.completed -or $null -ne $group.source_result){throw 'Incomplete IPI invented completed broadcast/source result.'};foreach($member in @($group.members)){if($member.phase -ne 'Returned' -and $null -ne $member.result){throw 'Unreturned callback fabricated a result.'}}}
   if($case.name -eq 'descriptor-mutation' -and (-not $r.descriptor_guard_installed -or $r.descriptor_denials -le 0)){throw 'Guest descriptor mutation escaped owned memory guard.'}
   if($case.lowered){$t=$e.kernel_threads;$rootTask=@($t.states|Where-Object {$_.slot -eq 1});if($t.count -ne 2 -or $t.exited -ne 0 -or $t.open_thread_handles -ne 1 -or $t.waits -ne 2 -or $t.resumed_waits -ne 1 -or $null -ne $t.root_entry_return -or $rootTask[0].state -ne 'Running' -or @($owned.handles).Count -ne 1){throw 'Lowered IPI mutated/retired the real caller scheduler lifetime.'}}
  }else{
   if($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'IPI budget prefix fabricated an entry return.'}}
   elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "IPI guest row/ABI/restoration checks failed $arch ${kind}: $($e.error)"}
   $groupCount=if($case.repeat){2}else{1};$value=if($case.name -eq 'wide' -and $arch -eq 'x64'){[uint64]0x1234567800001234}else{[uint64]0x1234}
   if($groups.Count -ne $groupCount -or $r.native_effect_failure -or $r.processors.native_effect_failure -or $r.current_processor -ne 0 -or $r.processors.current_processor -ne 0 -or $null -ne $r.rendezvous.active -or $null -ne $r.rendezvous.current){throw 'IPI failed to restore the actual source processor or falsely completed a native effect.'}
   $sourceThread=if($case.name -eq 'child-caller'){@($owned.threads|Where-Object {$_.slot -eq 2 -and $_.role -eq 'CreatedSystemThread'})[0].address}else{$caller[0].address}
   foreach($group in $groups){if(-not $group.completed -or $group.source_processor -ne 0 -or $group.caller_thread -ne $sourceThread -or $group.source_result -ne $value -or @($group.members).Count -ne $case.logical){throw 'IPI source result/current Thread lacks real callback evidence.'};foreach($member in @($group.members)){if(-not $member.started -or $member.phase -ne 'Returned' -or $member.instruction_count -le 0 -or $member.result -ne $value+$member.processor){throw 'IPI callback has no matching actual native return.'}}}
   $complete=@($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.KeIpiGenericCall' -and -not $_.pending -and $_.effect -eq 'ipi_broadcast_complete'});if($complete.Count -ne $groupCount -or @($complete|Where-Object {$_.result -ne $value -or $_.execution_domain -ne 'ordinary_thread'}).Count){throw 'IPI resumed another API observation or lost ULONG_PTR width.'}
   $callbacks=@($e.api_events|Where-Object {$_.execution_domain -eq 'ipi_member'});if($callbacks.Count -ne 3*$case.logical*$groupCount -or @($callbacks|Where-Object {$_.thread_id -ne 0 -or $_.processor -ge $case.logical}).Count){throw 'IPI callbacks were claimed as invented ordinary scheduler thread slots.'}
   $parked=@($owned.threads|Where-Object {$null -ne $_.role.ParkedProcessor});if($parked.Count -ne $case.logical-1){throw 'IPI parked environments were duplicated or omitted.'};foreach($row in $parked){$body=@($objects.objects|Where-Object {$_.address -eq $row.address})[0];if($row.slot -ne 0 -or $row.root_caller -or $row.executing -or $row.terminated -or $row.retired -or $row.open_handles -ne 0 -or -not $body.live -or $body.permanent_references -ne 1 -or $body.api_references -ne 0){throw 'IPI borrowed parked ownership was confused with real thread execution/handles.'}}
   $extra=if($case.child){1}else{0};if(@($objects.objects).Count -ne $case.logical+2+$extra -or @($owned.handles).Count -ne 0 -or @($r.processors.processors).Count -ne $case.logical -or @($r.processors.processors|Where-Object {-not $_.prepared}).Count){throw 'IPI processor resources/handles/lifetime anchors differ from actual configured members.'}
   if($case.child){$expectedExits=2-[int]$partial;if($e.kernel_threads.count -ne 2 -or $e.kernel_threads.exited -ne $expectedExits -or $e.kernel_threads.open_thread_handles -ne 0){throw 'IPI parked or invented an actual guest-created child routine.'}}
   elseif($null -ne $e.kernel_threads){throw 'IPI fabricated ordinary scheduler threads for remote parked processors.'}
   if($case.msr){foreach($processor in @($r.processors.processors)){$number=[uint64]$processor.layout.processor;if($processor.msrs.'3221225731' -ne 0x80+$number -or $processor.tsc_adjust -ne 0x100+$number){throw 'Native context restore leaked or rolled back perCPU committed MSR/TSC state.'}}}
  }
  foreach($event in @($e.api_events|Where-Object {$_.pending})){if($null -ne $event.result){throw 'Pending IPI invented its source return.'}}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;groups=$groups.Count;reused=[bool]$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 75){throw 'IPI control count mismatch.'}
Write-Output "Verified $($records.Count) contained actual guest IPI processor/ABI/barrier/perCPU-state/restoration/failure/budget controls."
$global:LASTEXITCODE=0
