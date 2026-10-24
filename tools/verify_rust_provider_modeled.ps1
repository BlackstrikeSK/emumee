param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing thread evidence; choose fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(@{suffix='';calls=37},@{suffix='-unmodeled-code';calls=38;protected=$true})
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-provider-mixed'+$case.suffix;$negative=[bool]$case.protected;$calls=$case.calls;$modes=@('full');if(-not $case.protected){$modes+='before-return'}
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
  $e=$result.execution
  if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Mixed provider worker containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $e.api_calls -ne $calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0){throw 'Mixed provider actual native/API evidence mismatch.'}
  $lookups=@($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.MmGetSystemRoutineAddress'})
  $resolveCount=if($case.protected){20}else{19};if($lookups.Count -ne $resolveCount -or @($lookups|Select-Object -First 19|Where-Object {$null -eq $_.result -or $_.result -eq 0}).Count){throw 'Delegated routine was not really resolved after provider binding.'}
  if($negative){$expected=if($arch -eq 'x64'){'FETCH_PROT'}else{'Unmodeled synthetic provider export'};if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $expected){throw 'Unmodeled provider export became executable or reported fake success.'};if($arch -eq 'x64' -and @($e.provider_denials|Where-Object {$_.name -eq 'KeInsertQueueDpc' -and $_.kind -eq 'code'}).Count -eq 0){throw 'Unmodeled catalog code lost exact symbol denial.'}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Mixed provider budget prefix fabricated a driver return.'}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Mixed MDL/rundown/bugcheck dispatch or guest address/coherence checks failed $arch $kind $($e.error)"}
  if($case.protected -and $arch -eq 'x86' -and $null -ne $lookups[-1].result){throw 'x86 provider invented unmodeled export availability/result.'}
  $mdl=$e.kernel_mdls;$run=$e.kernel_cache_aware_rundown;$callback=$e.kernel_callbacks;$pool=$e.kernel_pool
  if($null -eq $mdl -or $mdl.native_effect_failure -or $mdl.owned_backing_pages -ne 0 -or $null -eq $run -or $run.native_effect_failure -or @($run.references).Count -ne 0 -or @($run.blocked_teardowns).Count -ne 0 -or $null -eq $callback -or $callback.native_effect_failure -or -not $callback.owned_list_head_initialized -or @($callback.bugcheck.registered).Count -ne 0 -or $callback.bugcheck.callbacks_executed -ne 0 -or $callback.named.callbacks_executed -ne 0 -or $pool.mapped_bytes -ne 0 -or $pool.total_allocations -ne $pool.total_frees){throw 'Mixed provider lifecycle leaked state or invented callbacks.'}
  if(@($e.synthetic_providers|Where-Object {$_.module -eq 'ntoskrnl.exe'}).Count -ne 1){throw 'Mixed provider target did not actually publish ntoskrnl.'}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;reused=[bool]$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 6){throw 'Mixed provider control count mismatch.'}
Write-Output "Verified $($records.Count) contained mixed-provider resolution, actual MDL/rundown/bugcheck lifetime, untouched catalog protections and budget controls."
$global:LASTEXITCODE=0
