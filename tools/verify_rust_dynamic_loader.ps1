param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve dynamic-loader evidence; select a fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'Dynamic-loader frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "Dynamic-loader frozen binary mismatch: $($binding.file)."}
}

$cases=@(
 @{name='basic-a';positive=$true},@{name='basic-w';positive=$true},@{name='ex-a';positive=$true},@{name='ex-w';positive=$true},@{name='ldr';positive=$true},@{name='retain';positive=$true},@{name='reload';positive=$true},@{name='tls';positive=$true},@{name='dependency';positive=$true},@{name='forwarder';positive=$true},@{name='static-retain';positive=$true},@{name='false';positive=$true},
 @{name='attach-budget';budget=$true},@{name='detach-budget';budget=$true},@{name='fault'},@{name='reentry';error='reentrancy is not modeled'},@{name='storage-tls';error='TLS template/index/zero-fill'},@{name='nx-callback'},@{name='missing-dependency';error='no modeled finite external binding'},
 @{name='missing';positive=$true},@{name='malformed';positive=$true},@{name='flags';error='nonzero file/flags'},
 @{name='ldr-bad-bounds';positive=$true;structural=$true},@{name='ldr-bad-maximum';positive=$true;structural=$true},@{name='ldr-bad-output';positive=$true;structural=$true},@{name='ldr-flags';positive=$true;structural=$true},@{name='ldr-null';positive=$true;structural=$true},@{name='ldr-counted-nul';positive=$true;structural=$true},
 @{name='unmapped-fetch';error='FETCH_UNMAPPED'},@{name='ldr-false';positive=$true},@{name='ldr-no-output';positive=$true},@{name='ldr-output-readonly';error='lacks permission2'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='dynamic-loader-'+$case.name;$modes=@('full');if($case.positive){$modes+='before-return'};if($case.name -ceq 'tls'){$modes+='after-attach'}
 foreach($mode in $modes){
  if($mode -ceq 'full'){$budget=10000}else{
   $baseline=@($records|Where-Object {$_.arch -ceq $arch -and $_.kind -ceq $kind -and $_.mode -ceq 'full'})
   if($baseline.Count -ne 1){throw 'Missing dynamic-loader exact budget baseline.'}
   if($mode -ceq 'before-return'){$budget=$baseline[0].instructions-1}else{$budget=$baseline[0].attach_boundary}
   if($budget -le 0){throw 'Invalid real attach/caller instruction boundary.'}
  }
  $run=Join-Path $root ($arch+'-'+$kind+'-'+$mode);$reused=Test-Path -LiteralPath $run
  if(-not $reused){& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}elseif(-not $Resume){throw 'Never overwrite existing dynamic-loader evidence.'}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultPath=Join-Path $run 'fixture-result.json';$resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Dynamic-loader run belongs to another frozen build.'}}
  if($manifest.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -cne $kind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget){throw 'Dynamic-loader request/result/build/cleanup binding failed.'}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Dynamic-loader packaged offline containment failure.'}
  $e=$result.execution;$r=$e.dynamic_loader;if($reused){$exit=if($e.completion_reason -ceq 'entry_return'){0}else{1}}
  if($e.backend -cne 'rust/unicorn-x86' -or $e.architecture -cne $arch -or $e.network.calls -ne 0 -or $null -ne $e.kernel_threads -or $null -ne $e.kernel_ipi -or $e.api_events_omitted -ne 0){throw 'Dynamic-loader execution domain/profile mismatch.'}
  if($null -ne $r){
   if($r.profile -cne 'bounded-vfs-leaf-dll-v1' -or $r.state.owner -ne 1024 -or $null -ne $r.native_effect_failure -or $r.state.events_omitted -ne 0 -or $r.state.routines_omitted -ne 0){throw 'Dynamic-loader ownership/effect/evidence mismatch.'}
   foreach($event in @($r.state.routines)){if($null -eq $event.stopped_instructions -or $event.stopped_instructions -lt $event.started_instructions -or $event.stopped_instructions -gt $e.instruction_count -or ($null -eq $event.returned_value -and $null -eq $event.failure) -or $event.invocation.arguments[2] -ne 0){throw 'Dynamic-loader routine is not a genuine bounded native ABI phase.'}}
   foreach($retired in @($r.state.retired)){if(@($r.images|Where-Object {$_.id -eq $retired.id}).Count -ne 0 -or $retired.image.owner -ne 1024 -or $retired.image.phase -cne 'detaching'){throw 'Actually retired DLL retained a live catalog identity.'}}
  }
  if($mode -cne 'full'){
   if($exit -ne 1 -or $e.completion_reason -cne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.error -or $null -ne $e.guest_entry_return){throw 'Dynamic-loader prefix fabricated whole-program completion or reset the shared horizon.'}
   if($mode -ceq 'after-attach'){
    if($null -eq $r -or $null -eq $r.pending_api -or -not $r.state.active.returning -or @($r.images).Count -ne 1 -or $r.images[0].dynamic.phase -cne 'ready' -or $r.images[0].api_references -ne 1 -or @($e.api_events|Where-Object {$_.pending -and $null -eq $_.result -and $_.effect -ceq 'dynamic_loader_pending'}).Count -ne 1){throw 'Real initialized DLL/reference was confused with a completed caller API RET.'}
   }
  }elseif($case.positive){
   if($exit -ne 0 -or $e.completion_reason -cne 'entry_return' -or $e.guest_entry_return -ne 42 -or $null -ne $e.error){throw "Real DLL/VFS guest checks failed: $kind/$arch $($e.error)"}
   if($case.structural){if($null -ne $r){throw 'Structural Ldr failure issued an unnecessary loader operation.'}}
   else{
    if($null -eq $r -or $null -ne $r.pending_api -or $null -ne $r.state.active -or $r.requests -ne $r.resumed){throw 'Successful guest program has an unfinished DLL operation.'}
    foreach($event in @($r.state.routines)){if($null -eq $event.returned_value -or $null -ne $event.failure){throw 'Completed DLL operation lacks actual routine returns.'}}
    $retired=if($case.name -in @('missing','malformed','static-retain')){0}elseif($case.name -in @('dependency','forwarder','reload')){2}else{1}
    if(@($r.state.retired).Count -ne $retired -or @($r.images).Count -ne 0){throw 'Dynamic-loader exact live/retired image count mismatch.'}
    if($case.name -in @('false','ldr-false')){
     $status=if($case.name -ceq 'false'){0}else{0xc0000142L}
     $returns=@($e.api_events|Where-Object {$_.effect -ceq 'dynamic_loader_return_ready'})
     if(@($r.state.routines).Count -ne 4 -or $r.state.routines[1].invocation.routine -cne 'dll_attach' -or $r.state.routines[1].returned_value -ne 0 -or $r.state.routines[2].invocation.routine -cne 'tls_detach' -or $r.state.routines[3].invocation.routine -cne 'dll_detach' -or $returns.Count -ne 1 -or $returns[0].result -ne $status -or $returns[0].last_error -ne 1114){throw 'Failed load lacks real FALSE, own cleanup or deferred NT/Win32 result.'}
    }
    if($case.name -in @('dependency','forwarder')){
     if($r.state.retired[0].name -cne 'guest.dll' -or $r.state.retired[1].name -cne 'other.dll' -or @($r.state.retired[0].released_dependencies).Count -ne 1 -or $r.state.retired[0].released_dependencies[0] -ne $r.state.retired[1].id -or @($r.state.routines).Count -ne 4 -or $r.state.routines[2].invocation.module -ne $r.state.retired[0].id -or $r.state.routines[3].invocation.module -ne $r.state.retired[1].id){throw 'Installed IAT/followed-forwarder ownership did not release in actual cascade order.'}
     if($case.name -ceq 'forwarder' -and @($r.state.events|Where-Object {$_.kind -ceq 'followed_forwarder_dependencies_acquired' -and $_.module -eq $r.state.retired[0].id -and $_.dependencies -contains $r.state.retired[1].id}).Count -ne 1){throw 'Late followed forwarder has no actual committed target identity.'}
    }
    if($case.name -ceq 'reload' -and ($r.state.retired[0].base -ne $r.state.retired[1].base -or $r.state.retired[0].id -ge $r.state.retired[1].id -or $r.state.retired[0].provenance.accepted_image_sha256 -cne $r.state.retired[1].provenance.accepted_image_sha256)){throw 'Reload lost fresh catalog generation or immutable accepted bytes.'}
    if($case.name -ceq 'static-retain'){$module=@($e.native_loader.images|Where-Object {$_.name -ceq 'guest.dll'});if($module.Count -ne 1 -or -not $module[0].lifecycle.static_anchor -or $module[0].api_references -ne 0 -or @($r.state.routines).Count -ne 0 -or @($e.native_loader.events).Count -ne 1){throw 'Acquired API ref consumed a process anchor or invented duplicate initialization.'}}
   }
  }else{
   $completion=if($case.budget){'instruction_budget'}else{'error'}
   if($exit -ne 1 -or $e.completion_reason -cne $completion -or $null -ne $e.guest_entry_return){throw "Dynamic-loader refusal/fault invented completed entry: $kind/$arch"}
   if($case.error -and $e.error -notmatch [regex]::Escape($case.error)){throw "Wrong dynamic-loader refusal: $kind/$arch $($e.error)"}
   if($case.name -ceq 'flags'){if($null -ne $r){throw 'Unsupported flags queued a DLL operation.'}}
   elseif($case.name -ceq 'unmapped-fetch'){if($null -eq $r -or $null -ne $r.pending_api -or @($r.state.retired).Count -ne 1 -or @($r.images).Count -ne 0 -or $null -ne $r.state.active){throw 'Real post-unload export fetch did not fault after actual retirement.'}}
   elseif($case.name -ceq 'ldr-output-readonly'){
    if($null -eq $r -or $null -eq $r.pending_api -or $null -ne $r.pending_result -or @($r.images).Count -ne 1 -or $r.images[0].dynamic.phase -cne 'ready' -or $r.images[0].api_references -ne 1 -or @($r.state.retired).Count -ne 0 -or @($e.api_events|Where-Object {$_.api -ceq 'ntdll.LdrLoadDll' -and $_.pending -and $null -eq $_.result}).Count -ne 1){throw 'Output publication failure erased real initialization/reference or fabricated a result.'}
   }else{
    if($null -eq $r -or $null -eq $r.pending_api -or $null -ne $r.pending_result -or @($r.state.retired).Count -ne 0 -or @($r.images|Where-Object {$_.api_references -ne 0}).Count -ne 0){throw 'Unfinished dynamic DLL operation fabricated a reference/retirement/API result.'}
    if($case.budget){$expected=if($case.name -ceq 'attach-budget'){2}else{4};if($e.instruction_count -ne $budget -or $null -ne $e.error -or -not $r.state.active.interrupted -or @($r.state.routines).Count -ne $expected -or $null -ne $r.state.routines[-1].returned_value -or $null -eq $r.state.routines[-1].failure){throw 'Actual callback loop reset the shared budget or invented a return.'}}
    elseif($case.name -in @('fault','reentry')){if(-not $r.state.active.interrupted -or $null -ne $r.state.routines[-1].returned_value){throw 'Faulted callback was counted as returned.'}}
    elseif(@($r.images).Count -ne 0 -or @($r.state.routines).Count -ne 0){throw 'Refused leaf/TLS profile published an image or executed a callback.'}
   }
  }
  $boundary=$null;if($null -ne $r){$first=@($r.state.events|Where-Object {$_.kind -ceq 'caller_api_result_published'}|Select-Object -First 1);if($first.Count -eq 1){$boundary=$first[0].instruction}}
  $records+=@{arch=$arch;kind=$kind;mode=$mode;instructions=$e.instruction_count;attach_boundary=$boundary;completion=$e.completion_reason;request_sha256=$requestHash;result_sha256=$resultHash;run=$run;reused=$reused}
  @{source_tree_sha256=$receipt.source_tree_sha256;status='in-progress';verified=$records.Count;records=$records}|ConvertTo-Json -Depth 25|Set-Content -LiteralPath (Join-Path $root 'dynamic-loader-verification.json') -Encoding utf8
 }
}}
if($records.Count -ne 110){throw 'Dynamic-loader exact full/prefix control count mismatch.'}
@{source_tree_sha256=$receipt.source_tree_sha256;status='passed';verified=$records.Count;records=$records}|ConvertTo-Json -Depth 25|Set-Content -LiteralPath (Join-Path $root 'dynamic-loader-verification.json') -Encoding utf8
$global:LASTEXITCODE=0
Write-Output '110 dynamic-loader contained controls passed.'
