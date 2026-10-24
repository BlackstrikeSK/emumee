param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$ThreadControls,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve object evidence; use explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$bundlePath=Split-Path -Parent $exe
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
foreach($pair in @(@('emumee-rs.exe','controller_sha256'),@('emumee-worker.exe','worker_sha256'),@('unicorn.dll','unicorn_sha256'))){if((Get-FileHash -LiteralPath (Join-Path $bundlePath $pair[0]) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receipt.($pair[1])){throw 'Object frozen binary hash mismatch.'}}
$objectCount=if($ThreadControls){3}else{2}
$handleError=if($ThreadControls){'Foreign process/file'}else{'handle ownership is not integrated'}
$cases=@(
 @{name='kernel-objects-lifecycle';calls=9;events=6},@{name='kernel-objects-data-only';calls=0},
 @{name='kernel-objects-kernel-mismatch';calls=2;events=2},@{name='kernel-objects-user-mismatch';calls=1},
 @{name='kernel-objects-user-access';calls=1;error='UserMode object security/access validation'},
 @{name='kernel-objects-mode';calls=1;error='unsupported object reference access mode'},
 @{name='kernel-objects-underflow';calls=1;error='cannot consume permanent System/Driver ownership'},
 @{name='kernel-objects-foreign';calls=1;error='live owned object body'},
 @{name='kernel-objects-irql';calls=2;error='above DISPATCH_LEVEL'},
 @{name='kernel-objects-global-write';calls=0;error='WRITE_PROT'},@{name='kernel-objects-global-call';calls=0;error='FETCH_PROT'},
 @{name='kernel-objects-identity-read';calls=0;error='READ_PROT';denial=$true},@{name='kernel-objects-identity-call';calls=0;error='FETCH_PROT';denial=$true},
 @{name='kernel-objects-type-read';calls=0;error='READ_PROT';denial=$true},@{name='kernel-objects-type-call';calls=0;error='FETCH_PROT';denial=$true},
 @{name='kernel-objects-api-identity-read';calls=1;error='private kernel EPROCESS';denial=$true},
 @{name='kernel-objects-api-identity-write';calls=1;error='private kernel EPROCESS';denial=$true},
 @{name='kernel-objects-by-handle';calls=1;error=$handleError}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $case.name -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing object budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=1000}
  $run=Join-Path $root ($arch+'-'+$case.name+$(if($partial){'-partial'}else{''}))
  $reused=Test-Path -LiteralPath $run
  if($reused){if(-not $Resume){throw 'Existing object run requires Resume.'};$exit=$null}else{& $exe fixture --kind $case.name --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $request=Get-Content -LiteralPath (Join-Path $run 'request.json') -Raw|ConvertFrom-Json
  $stop=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath (Join-Path $run 'request.json') -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultHash=(Get-FileHash -LiteralPath (Join-Path $run 'fixture-result.json') -Algorithm SHA256).Hash.ToLowerInvariant()
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Object frozen run hash mismatch.'}}
  if($request.kind -cne $case.name -or $request.architecture -cne $arch -or $request.iterations -ne 1000000 -or $request.max_instructions -ne $budget -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $manifest.cleanup -cne 'restored' -or $stop.cleanup -cne 'restored' -or $stop.exit_code -ne 0){throw 'Object exact request/result/cleanup binding mismatch.'}
  if($reused){$saved=Get-Content -LiteralPath ($run+'.console.log') -Raw|ConvertFrom-Json;if(($saved|ConvertTo-Json -Depth 100 -Compress) -cne ($manifest|ConvertTo-Json -Depth 100 -Compress)){throw 'Saved object controller stdout differs from final manifest.'}}
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  if($result.request_sha256 -cne $requestHash){throw 'Object result request binding mismatch.'}
  $e=$result.execution;$r=$e.kernel_objects
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Object packaged offline worker containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $null -eq $r -or $e.api_calls -ne $case.calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0){throw "Object native/kernel/offline report mismatch $arch $($case.name)."}
  if($case.error){if((-not $reused -and $exit -ne 1) -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error){throw "Object negative mismatch $arch $($case.name): $($e.error)"}}
  elseif($partial){if((-not $reused -and $exit -ne 1) -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Object budget stop fabricated an entry return.'}}
  elseif((-not $reused -and $exit -ne 0) -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Object ownership/ABI/identity checks failed $arch $($case.name): $($e.error)"}
  $width=if($arch -eq 'x64'){8}else{4}
  if($r.system_pid -ne 4 -or $r.system_process -ne $r.driver_object+0x3000 -or $r.driver_object -ne $e.kernel_entry.layout.driver_object -or -not $r.driver_object_initialized -or @($r.types).Count -ne 12 -or @($r.objects).Count -ne $objectCount -or @($r.storage).Count -ne 13 -or @($r.events).Count -ne [int]$case.events -or $r.events_omitted -ne 0 -or $r.native_effect_failure){throw 'Object permanent ownership/type/export/event state mismatch.'}
  foreach($row in @($r.objects)){if($row.permanent_references -ne 1 -or $row.api_references -ne 0 -or -not $row.live){throw 'Transient API references consumed permanent ownership or leaked.'}}
  if(@($r.types|Select-Object -ExpandProperty identity -Unique).Count -ne 12 -or @($r.storage|Select-Object -ExpandProperty address -Unique).Count -ne 13){throw 'Opaque type identities or pointer storages overlap.'}
  foreach($row in @($r.storage)){if($row.width -ne $width -or $row.permissions -ne 'r--' -or $row.address -eq $row.value -or $row.value -eq 0){throw 'Object typed export width/permission/identity mismatch.'}}
  if($case.denial -and @($r.api_denials).Count -eq 0){throw 'Opaque kernel object access lacked denial evidence.'}
  if($case.name -eq 'kernel-objects-user-mismatch' -and $e.api_events[0].result -ne 3221225508){throw 'UserMode object type mismatch did not return STATUS_OBJECT_TYPE_MISMATCH.'}
  if(@($e.api_events|Where-Object {$_.api -notlike 'ntoskrnl.*' -or $_.last_error -ne 0}).Count){throw 'Object calls escaped guest kernel APIs or changed Win32 last error.'}
  $records+=@{original_controller_exit_known=(-not $reused);reused=$reused;request_sha256=$requestHash;result_sha256=$resultHash;arch=$arch;case=$case.name;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;verified=$true}
 }
}}
if($records.Count -ne 44){throw 'Object control count mismatch.'}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained kernel object identity/permanent-reference/type/READ-NX/unsupported-handle/budget controls."
$global:LASTEXITCODE=0
