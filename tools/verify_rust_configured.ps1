param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$exe=Join-Path $bundlePath 'emumee-rs.exe'
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'Configured frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "Configured frozen binary differs from receipt: $($binding.file)."}
}
foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($receipt.$key -cnotmatch '^[a-f0-9]{64}$'){throw 'Configured frozen digest missing.'}}
function Expected-ConfiguredReturn([string]$Case){if($Case -ceq 'ipi'){return 1};return 17}
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing configured-native evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@('user-a','user-w','empty-a','empty-w','kernel','ipi')
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){foreach($mode in @('full','before-return')){
 $kernel=$case -in @('kernel','ipi');$empty=$case -like 'empty-*';$partial=$mode -eq 'before-return';$kind='configured-'+$case
 if($partial){$prior=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $kind -and -not $_.partial});if($prior.Count -ne 1){throw 'Configured instruction baseline missing.'};$budget=$prior[0].instructions-1}else{$budget=20000}
 $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
 & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
 $exit=$LASTEXITCODE
 $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
 $requestPath=Join-Path $run 'request.json';$resultPath=Join-Path $run 'fixture-result.json'
 $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
 $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
 $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
 $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
 foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Configured run belongs to another frozen build.'}}
 if($manifest.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $request.kind -cne $kind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000){throw 'Configured request/result/build/worker-exit/cleanup binding failed.'}
 $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
 if($result.request_sha256 -cne $requestHash){throw 'Configured result request hash mismatch.'}
 $e=$result.execution;$c=$e.configuration
 if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Configured fixture containment mismatch.'}
 if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $c -or -not $c.initialized -or -not $c.generated_only -or $c.version -cne 'emumee-configured-native-v1' -or $c.pending.Count -lt 42){throw 'Configured actual backend/receipt/pending mismatch.'}
 foreach($hash in @($c.input_json_sha256,$c.effective_sha256,$c.projection_sha256,$c.seed_manifest_sha256)){if($hash -cnotmatch '^[a-f0-9]{64}$'){throw 'Configured digest binding missing.'}}
 if($c.windows_build -ne 26100 -or $c.physical_memory_mb -ne 8192 -or $c.available_memory_mb -ne 4096 -or $c.initial_processor -ne 0 -or $c.seeded_files -ne $(if($empty){0}else{1}) -or $c.seeded_registry_keys -ne $(if($empty){0}else{1})){throw 'Configured nondefault machine/seed values mismatch.'}
 if($e.network.calls -ne 0 -or $e.artifacts.Count -ne 0 -or $null -ne $e.error -or $e.api_events_omitted -ne 0 -or @($e.api_events|Where-Object {$null -ne $_.error}).Count){throw 'Configured input bytes mislabeled output, API error, or host/network effects.'}
 if($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return){throw 'Configured prefix fabricated entry return.'}}
 elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne (Expected-ConfiguredReturn $case)){throw "Configured guest observations failed $arch ${kind}: $($e.error)"}
 if($kernel){
  if($null -eq $e.kernel_cpu -or $null -ne $c.user_process_owner -or $e.kernel_environment.identity.windows_build -ne 26100 -or $e.kernel_environment.identity.current_processor -ne 0 -or $e.kernel_environment.identity.logical_processors -ne $(if($case -eq 'ipi'){4}else{6})){throw 'Configured kernel profile/selected CPU inconsistency.'}
  if($case -eq 'ipi'){$b=@($e.kernel_ipi.rendezvous.broadcasts);if($b.Count -ne 1 -or -not $b[0].completed -or $b[0].members.Count -ne 4 -or @($b[0].members|Where-Object {-not $_.started -or $_.instruction_count -le 0 -or $null -eq $_.result}).Count -or $e.kernel_ipi.current_processor -ne 0){throw 'Configured actual IPI callbacks/caller restoration mismatch.'}}
 }else{
  if($null -ne $e.kernel_cpu -or $c.user_process_owner -ne 1024 -or $c.guest_image_path -cne 'C:\Users\Morgan\Downloads\configured-probe.exe' -or $e.file_storage.open_handles -ne 0 -or $e.environment_blocks.lifetime_allocations -ne 1 -or $e.environment_blocks.mapped_bytes -ne 0 -or $e.environment_blocks.live.Count -ne 0 -or $e.environment_blocks.events.Count -ne 2){throw 'Configured process invocation/owned snapshot/file cleanup mismatch.'}
  $roots=@($e.loaded_modules|Where-Object {$_.name -eq 'configured-probe.exe'});if($roots.Count -ne 1 -or @($e.loaded_modules|Where-Object {$_.name -eq 'generated-fixture.exe'}).Count){throw 'Configured loader identity retained fixture name.'}
  $events=@($e.api_events);if($events[-1].last_error -ne 0x12345678){throw 'Configured registry/LastError contract mismatch.'}
  if($arch -eq 'x64' -and @($e.environment_blocks.events|Where-Object {$_.operation -eq 'allocated' -and $_.address -gt [uint32]::MaxValue}).Count -ne 1){throw 'Configured environment block truncated fullwidth guest pointer.'}
 }
 $records+=@{arch=$arch;case=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;effective_sha256=$c.effective_sha256;projection_sha256=$c.projection_sha256;seed_manifest_sha256=$c.seed_manifest_sha256;source_tree_sha256=$receipt.source_tree_sha256;request_sha256=$requestHash;result_sha256=$resultHash;worker_exit_code=$workerExit.exit_code;cleanup=$workerExit.cleanup;verified=$true}
 $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
}}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 24){throw 'Configured native control count mismatch.'}
Write-Output "Verified $($records.Count) contained configured-authority/identity/seed/clock/machine/IPI/budget controls."
$global:LASTEXITCODE=0
