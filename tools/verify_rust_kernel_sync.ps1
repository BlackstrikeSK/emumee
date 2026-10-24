param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing synchronization evidence; choose fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(
 @{name='rundown';calls=8},@{name='push';calls=5},@{name='push-flag-width';calls=5},@{name='irql';calls=14},@{name='native-irql';calls=3},@{name='lower-alias';calls=14},
 @{name='rundown-blocked';calls=3;error='Blocked rundown wait requires kernel thread scheduling'},
 @{name='rundown-release';calls=2;error='Rundown release without a reference'},
 @{name='rundown-overflow';calls=1;error='Rundown reference count overflow'},
 @{name='push-blocked';calls=4;error='Blocked push-lock acquisition requires kernel thread scheduling'},
 @{name='push-release';calls=3;error='Exclusive push-lock release without exclusive ownership'},
 @{name='push-tamper';calls=4;error='Exclusive push-lock release without exclusive ownership'},
 @{name='push-flags';calls=3;error='Unsupported push-lock flags'},
 @{name='push-apcs';calls=2;error='Push-lock operation requires disabled normal kernel APCs'},
 @{name='unaligned';calls=1;error='Synchronization word is not pointer aligned'},
 @{name='read-only';calls=1;error='range'},@{name='invalid-range';calls=1;error='range'},
 @{name='high-irql';calls=2;error='Synchronization operation above supported IRQL'},
 @{name='invalid-raise';calls=1;error='Invalid IRQL raise'},@{name='invalid-lower';calls=1;error='Invalid IRQL lower'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-sync-'+$case.name;$negative=[bool]$case.error;$calls=$case.calls;$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing kernel-wait budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=10000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}));$reused=Test-Path -LiteralPath $run
  if($reused){if(-not $Resume){throw 'Never overwrite an existing generated synchronization run.'}}
  else{& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultPath=Join-Path $run 'fixture-result.json';$resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Synchronization run belongs to another frozen build.'}}
  if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -ne $kind -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget){throw 'Synchronization request/result/build/cleanup binding failed.'}
  $e=$result.execution
  if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Synchronization packaged offline containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $e.api_calls -ne $calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or $null -ne $e.kernel_threads -or $e.kernel_state.scalar_sync_omitted -ne 0){throw 'Synchronization native/API evidence mismatch.'}
  if($negative){
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error -or $null -ne $e.api_events[-1].result){throw 'Rejected synchronization fabricated completion.'}
   if($case.name -eq 'rundown-blocked'){$row=$e.kernel_state.scalar_sync[-1];if($row.before -ne 2 -or $row.after -ne 3 -or -not $row.wrote -or $row.completed){throw 'Pending rundown bit was not committed before unsupported wait.'}}
   elseif($case.name -eq 'push-blocked'){$row=$e.kernel_state.scalar_sync[-1];if($row.before -ne 1 -or $row.after -ne 1 -or $row.wrote -or $row.completed){throw 'Contended push lock invented a grant or memory effect.'}}
   elseif(@($e.kernel_state.scalar_sync|Where-Object {-not $_.completed}).Count -ne 0){throw 'Rejected operation introduced a pending scalar effect.'}
   if($case.name -in @('invalid-raise','invalid-lower') -and ($e.kernel_state.irql -ne 0 -or $e.kernel_cpu.pcr_irql -ne 0)){throw 'Rejected IRQL alias changed actual processor state.'}
  }else{
   if($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Synchronization budget prefix fabricated guest completion.'}}
   elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Synchronization guest word/ABI/IRQL checks failed: $($e.error)"}
   if($e.kernel_state.irql -ne 0 -or $e.kernel_cpu.pcr_irql -ne 0 -or $e.kernel_state.critical_depth -ne 0 -or @($e.kernel_state.scalar_sync|Where-Object {-not $_.completed}).Count -ne 0){throw 'Synchronization left unproved completion or incorrect actual IRQL/critical state.'}
   if($case.name -eq 'rundown' -and (@($e.kernel_state.scalar_sync).Count -ne 8 -or $e.kernel_state.scalar_sync[-1].after -ne 1 -or $e.kernel_state.scalar_sync[-1].wrote)){throw 'Rundown pending bit/refusal evidence failed.'}
   if($case.name -in @('push','push-flag-width') -and (@($e.kernel_state.scalar_sync).Count -ne 3 -or $e.kernel_state.scalar_sync[-1].after -ne 0)){throw 'Push acquire/release actual word evidence failed.'}
  }
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;reused=[bool]$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 52){throw 'Synchronization control count mismatch.'}
Write-Output "Verified $($records.Count) contained rundown/push scalar, exact x86 ABI/stack, actual IRQL/APC, unsupported contention, guard and budget controls."
$global:LASTEXITCODE=0
