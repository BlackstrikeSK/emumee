param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing Kernel time evidence; choose a fresh root.'}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'Kernel time frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "Kernel time frozen binary differs from receipt: $($binding.file)."}
}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='local';calls=2},@{name='fields';calls=4},@{name='signed';calls=3},@{name='bounds';calls=2},
 @{name='alias-local';calls=1},@{name='partial-local';calls=1},@{name='alias-fields';calls=1},@{name='partial-fields';calls=1},
 @{name='resident-high';calls=2;irql=15},@{name='configured-positive';calls=2;configured=$true},@{name='configured-negative';calls=2;configured=$true},
 @{name='local-overflow';error='*signed local time overflow*'},@{name='calendar-low';error='*calendar outside legacy year1..9999 profile*'},
 @{name='calendar-high';error='*calendar outside legacy year1..9999 profile*'},@{name='readonly-local';error='*API guest range*'},
 @{name='readonly-fields';error='*API guest range*'},@{name='cross-page-local';error='*API guest range*'},
 @{name='cross-page-fields';error='*API guest range*'},@{name='unmapped-input';error='*API guest range*'},
 @{name='paged-input';error='*paged Pool access above APC_LEVEL*';irql=2;paged=1},@{name='paged-output';error='*paged Pool access above APC_LEVEL*';irql=2;paged=1}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-time-'+$case.name;$negative=[bool]$case.error;$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -ceq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -ceq $arch -and $_.kind -ceq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Kernel time actual instruction baseline missing.'};$budget=$baseline[0].instructions-1}else{$budget=20000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$resultPath=Join-Path $run 'fixture-result.json'
  $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($receipt.$key -cnotmatch '^[a-f0-9]{64}$' -or $manifest.$key -cne $receipt.$key){throw 'Kernel time run differs from frozen build receipt.'}}
  if($manifest.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -cne $kind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000){throw 'Kernel time exact request/result/worker-exit/cleanup binding failed.'}
  $e=$result.execution;$r=$e.kernel_rtl;$pool=$e.kernel_pool
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Kernel time packaged offline containment failure.'}
  if($e.backend -cne 'rust/unicorn-x86' -or $e.architecture -cne $arch -or $null -eq $r -or $null -eq $pool -or $null -eq $e.kernel_cpu -or ($e.kernel_cpu.current.cs -band 3) -ne 0 -or $null -ne $e.console -or $null -ne $e.crt_stdio -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or $e.api_events_omitted -ne 0){throw 'Kernel time actual guest-only backend/kernel provenance mismatch.'}
  if($r.native_effect_failure -or $r.events_omitted -ne 0 -or $r.formatting_omitted -ne 0 -or $r.capture_errors -ne 0 -or $r.lifetime_allocations -ne 0 -or $r.live_allocations -ne 0 -or @($r.owned).Count -ne 0 -or @($r.events).Count -ne 0 -or @($r.formatting).Count -ne 0){throw 'Time conversion fabricated RTL allocation/format state or hid a native effect failure.'}
  $paged=[int]$case.paged
  if($pool.total_allocations -ne $paged -or $pool.total_frees -ne 0 -or @($pool.allocations.PSObject.Properties).Count -ne $paged -or $pool.mapped_bytes -ne $paged*4096){throw 'Kernel time actual paged-memory prerequisite count mismatch.'}
  if($e.kernel_state.irql -ne [int]$case.irql -or ($arch -ceq 'x64' -and $e.cpu.cr8_writes -ne [int]([int]$case.irql -gt 0))){throw 'Kernel time did not use actual processor IRQL.'}
  if([bool]$case.configured){
   $configuration=$e.configuration
   if($null -eq $configuration -or -not $configuration.generated_only -or -not $configuration.initialized -or $configuration.windows_build -ne 26100 -or $configuration.initial_processor -ne 0 -or $null -ne $configuration.user_process_owner -or 'native_guest_clock' -cnotin $configuration.installed_components){throw 'Kernel time configured caller did not publish actual prevalidated seed installation.'}
   foreach($digest in @('input_json_sha256','effective_sha256','projection_sha256','seed_manifest_sha256')){if($configuration.$digest -cnotmatch '^[a-f0-9]{64}$'){throw 'Kernel time configured derivation digest missing.'}}
  }elseif($null -ne $e.configuration){throw 'Ordinary time fixture unexpectedly installed configured state.'}
  if($negative){if($exit -ne 1 -or $e.completion_reason -cne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "Kernel time honest refusal mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -cne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Kernel time exact prefix fabricated completion.'}}
  elseif($exit -ne 0 -or $e.completion_reason -cne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Kernel time guest exact bytes/poison/ABI/LastError assertions failed $arch ${kind}: $($e.error)"}
  $events=@($e.api_events)
  if(@($events|Where-Object {$_.last_error -ne 0x12345678 -or $_.thread_id -ne 1 -or $_.execution_domain -cne 'ordinary_thread'}).Count){throw 'Kernel time changed actual caller LastError/context.'}
  if(@($events|Where-Object {$_.api -notlike 'ntoskrnl.*' -and $_.api -notlike 'kernel32.*'}).Count){throw 'Kernel time fixture provider mismatch.'}
  if($negative){if($null -eq $events[-1].error -or @($events|Where-Object {$_.api -like '*.GetLastError'}).Count -ne 0){throw 'Kernel time refusal did not stop at actual API failure.'}}
  else{
   if(@($events|Where-Object {$null -ne $_.error}).Count){throw 'Successful time conversion fabricated API error.'}
   if($events[-1].api -notlike '*.GetLastError' -or $events[-1].result -ne 0x12345678){throw 'Kernel time actual GetLastError result missing.'}
   $conversions=@($events|Where-Object {$_.api -like '*.ExSystemTimeToLocalTime' -or $_.api -like '*.RtlTimeToTimeFields'})
   if($conversions.Count -ne [int]$case.calls -or @($conversions|Where-Object {$null -ne $_.result}).Count){throw 'Kernel time exact void-call observations mismatch.'}
  }
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;configured=[bool]$case.configured;irql=[int]$case.irql;source_tree_sha256=$receipt.source_tree_sha256;request_sha256=$requestHash;result_sha256=$resultHash;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 64){throw 'Kernel time control count mismatch.'}
Write-Output "Verified $($records.Count) contained signed time/offset/calendar/aliasing/ABI/configuration/IRQL/preflight/budget controls."
$global:LASTEXITCODE=0
