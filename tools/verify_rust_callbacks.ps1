param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing callback evidence; choose a fresh root.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='callback-namespace-unavailable';calls=1;error='ownership/type resolution is unavailable';unknown=$true},
 @{name='callback-bug-register';calls=1;bug=1},
 @{name='callback-bug-duplicate';calls=2;bug=1},
 @{name='callback-bug-deregister';calls=2},
 @{name='callback-bug-twice';calls=3},
 @{name='callback-bug-missing';calls=1},
 @{name='callback-bug-reason';calls=1},
 @{name='callback-bug-read-only';calls=1;error='lacks permission'},
 @{name='callback-bug-two-records';calls=3;bug=1},
 @{name='callback-create';calls=1;objects=1;refs=1},
 @{name='callback-missing';calls=1},
 @{name='callback-system';calls=1;objects=1;refs=2;permanent=$true;system=$true},
 @{name='callback-reopen';calls=2;objects=1;refs=2},
 @{name='callback-register';calls=2;objects=1;refs=2;regs=1;active=1},
 @{name='callback-duplicate';calls=3;objects=1;refs=2;regs=1;active=1},
 @{name='callback-multiple';calls=3;objects=1;refs=3;regs=2;active=2;multiple=$true},
 @{name='callback-unregister';calls=3;objects=1;refs=1;regs=1},
 @{name='callback-unregister-twice';calls=4;objects=1;refs=1;regs=1;error='invalid or inactive callback registration'},
 @{name='callback-notify-empty';calls=2;objects=1;refs=1},
 @{name='callback-notify-active';calls=3;objects=1;refs=2;regs=1;active=1;error='dispatch of registered guest routines is not modeled';blocked=1},
 @{name='callback-notify-system';calls=2;objects=1;refs=2;permanent=$true;system=$true;error='must not notify system-defined callback objects'},
 @{name='callback-dereference';calls=2;objects=1;refs=0},
 @{name='callback-permanent';calls=3;objects=1;refs=2;permanent=$true},
 @{name='callback-body-read';calls=1;objects=1;refs=1;error='READ_PROT';denial='CALLBACK_OBJECT'},
 @{name='callback-body-write';calls=1;objects=1;refs=1;error='WRITE_PROT';denial='CALLBACK_OBJECT'},
 @{name='callback-body-call';calls=1;objects=1;refs=1;error='FETCH_PROT';denial='CALLBACK_OBJECT'},
 @{name='callback-api-read';calls=2;objects=1;refs=1;error='unmodeled private callback';denial='CALLBACK_OBJECT'},
 @{name='callback-api-write';calls=2;objects=1;refs=1;error='unmodeled private callback';denial='CALLBACK_OBJECT'},
 @{name='callback-token-read';calls=2;objects=1;refs=2;regs=1;active=1;error='READ_PROT';denial='CALLBACK_REGISTRATION'},
 @{name='callback-irql';calls=2;error='above its supported IRQL'},
 @{name='callback-bad-length';calls=1},
 @{name='callback-odd-unicode';calls=1},
 @{name='callback-security';calls=1;error='root handles and security descriptors are not modeled'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){
   $baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $case.name -and -not $_.partial})
   if($baseline.Count -ne 1){throw 'Missing callback instruction baseline.'}
   $budget=$baseline[0].instructions-1
  }else{$budget=1000}
  $run=Join-Path $root ($arch+'-'+$case.name+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $case.name --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution;$callbacks=$e.kernel_callbacks;$named=$callbacks.named;$bug=$callbacks.bugcheck
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Callback packaged offline worker containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $null -eq $e.kernel_entry -or $null -eq $callbacks -or $e.api_calls -ne $case.calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0){throw "Callback native/kernel/offline report mismatch $arch $($case.name)."}
  if($case.error){
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error){throw "Callback negative mismatch $arch $($case.name): $($e.error)"}
  }elseif($partial){
   if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Callback budget stop fabricated entry return.'}
  }elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Callback guest status/pointer/record checks failed $arch $($case.name): $($e.error)"}
  $expectedNamespace=if($case.unknown){'Unavailable'}else{'OwnedGeneratedFixtureDirectory'}
  if($callbacks.namespace_authority -ne $expectedNamespace -or $callbacks.native_effect_failure -or @($callbacks.lifecycle_errors).Count -ne 0 -or $bug.callbacks_executed -ne 0 -or $named.callbacks_executed -ne 0 -or $named.pending_invocations -ne 0 -or @($callbacks.blocked_notifications).Count -ne [int]$case.blocked){throw 'Callback authority/lifecycle/real-execution accounting changed.'}
  if(@($bug.registered).Count -ne [int]$case.bug -or @($named.objects).Count -ne [int]$case.objects -or @($named.registrations).Count -ne [int]$case.regs -or @($named.registrations|Where-Object {$_.active}).Count -ne [int]$case.active){throw "Callback registrations/object count mismatch $arch $($case.name)."}
  $bugCase=$case.name -like 'callback-bug-*'
  if([bool]$callbacks.owned_list_head_initialized -ne $bugCase){throw 'Bug-check list-head lifetime mismatch.'}
  foreach($object in @($named.objects)){
   if($object.references -ne $case.refs -or [bool]$object.live -ne ($case.refs -gt 0) -or $object.permissions -ne '---' -or [bool]$object.permanent -ne [bool]$case.permanent -or [bool]$object.system -ne [bool]$case.system -or [bool]$object.allow_multiple -ne [bool]($case.multiple -or $case.system)){throw "Named callback object lifetime/attributes mismatch $arch $($case.name)."}
  }
  if($case.denial -and -not @($named.api_denials|Where-Object {$_.kind -eq $case.denial}).Count){throw 'Opaque callback body/token access lacked explicit denial evidence.'}
  if($case.blocked){
   $blocked=$callbacks.blocked_notifications[0]
   if($blocked.dispatched -ne 0 -or $blocked.registered -ne 1 -or $blocked.arguments[0] -ne 0x1111 -or $blocked.arguments[1] -ne 0x2222){throw 'Active callback notification fabricated dispatch.'}
  }
  if($case.name -eq 'callback-notify-empty'){
   $notify=@($named.events|Where-Object {$_.operation -eq 'notify'})
   if($notify.Count -ne 1 -or $notify[0].registered -ne 0 -or $notify[0].dispatched -ne 0){throw 'Empty callback notification changed semantics.'}
  }
  if(@($e.api_events|Where-Object {$_.api -notlike 'ntoskrnl.*' -or $_.last_error -ne 0}).Count){throw 'Callback call escaped guest kernel namespace or changed Win32 last error.'}
  $routine=if($arch -eq 'x64'){0x140001f00L}else{0x401f00L}
  if(@($e.instruction_tail|Where-Object {$_.pc -eq $routine}).Count){throw 'A callback body executed without guest scheduling support.'}
  if(@($e.artifacts).Count -ne [int]$case.bug){throw 'Callback typed memory capture count mismatch.'}
  foreach($artifact in @($e.artifacts)){
   if($artifact.filename -notmatch '^[0-9a-f]{64}\.bin$' -or $artifact.observations.Count -ne 1 -or $artifact.observations[0].source -ne 'kernel_bugcheck_record' -or $artifact.observations[0].kind -ne 'memory_snapshot'){throw 'Bug-check record capture provenance/type changed.'}
   $path=Join-Path (Join-Path $run 'artifacts') $artifact.filename;$bytes=[IO.File]::ReadAllBytes($path)
   $width=if($arch -eq 'x64'){8}else{4};$size=if($arch -eq 'x64'){48}else{28}
   if($bytes.Length -ne $size -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $artifact.sha256 -or $bytes[$width*5+4] -ne 1){throw 'Bug-check record capture bytes/hash/state mismatch.'}
   $readPointer={param([int]$offset) if($width -eq 8){[BitConverter]::ToUInt64($bytes,$offset)}else{[BitConverter]::ToUInt32($bytes,$offset)}}
   $head=if($arch -eq 'x64'){[Convert]::ToUInt64('ffffc10000000000',16)}else{[Convert]::ToUInt64('c1000000',16)}
   if((&$readPointer 0) -ne $head -or (&$readPointer $width) -ne $head -or (&$readPointer ($width*2)) -ne $routine){throw 'Bug-check linked record/routine pointer mismatch.'}
   $reason=if($case.name -eq 'callback-bug-two-records'){7}else{2}
   if([BitConverter]::ToUInt32($bytes,$width*5) -ne $reason -or $bug.registered[0].component -ne 'EMU'){throw 'Bug-check reason/component metadata changed.'}
  }
  $records+=@{arch=$arch;case=$case.name;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;actual_callback_execution=0;verified=$true}
 }
}}
if($records.Count -ne 106){throw 'Callback control count mismatch.'}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained callback authority/ABI/records/namespace/refs/private-access/budget controls; no callback execution claimed."
$global:LASTEXITCODE=0
