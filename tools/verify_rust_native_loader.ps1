param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve native-loader evidence; select a fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'Native-loader frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "Native-loader frozen binary mismatch: $($binding.file)."}
}

$cases=@(
 @{name='basic';events=1;positive=$true},@{name='tls';events=2;positive=$true},@{name='tls-only';events=1;positive=$true},@{name='nested';events=4;positive=$true},@{name='forwarded';events=2;positive=$true},@{name='root-dll';events=2;positive=$true},@{name='root-tls';events=1;positive=$true},@{name='entryless';events=0;positive=$true},
 @{name='false';events=4;retired=1;falseIndex=1},@{name='nested-false';events=8;retired=2;falseIndex=3},@{name='root-false';events=4;retired=1;falseIndex=1},@{name='cleanup-budget';events=8;budget=$true;retired=1;falseIndex=3},@{name='attach-budget';events=2;budget=$true},@{name='fault';events=2},@{name='bad-stack';events=1;error='stack return contract'},@{name='nonvolatile';events=1;error='protected/nonvolatile register'},@{name='tls-mutation';events=2;error='TLS callback directory/array differs'},@{name='detach-fault';events=3;falseIndex=1},
 @{name='unused';prepare=$true;error='unused supplied companion'},@{name='storage-tls';prepare=$true;error='TLS template/index/zero-fill'},@{name='missing-external';prepare=$true;error='not an actually modeled binding'},@{name='cycle';prepare=$true;error='static dependency cycle'},@{name='nx-callback';prepare=$true;error='not in an executable guest section'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='native-loader-'+$case.name;$modes=@('full');if($case.positive){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing native-loader budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=10000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}));$reused=Test-Path -LiteralPath $run
  if(-not $reused){& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}elseif(-not $Resume){throw 'Never overwrite existing native-loader run.'}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultPath=Join-Path $run 'fixture-result.json';$resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Native-loader run belongs to another frozen build.'}}
  if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -ne $kind -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget){throw 'Native-loader request/result/build/cleanup binding failed.'}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Native-loader packaged offline containment failure.'}

  $e=$result.execution;$report=$e.native_loader;if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  $expectedApis=if($case.name -ceq 'basic'){1}else{0}
  if($null -eq $report -or $report.profile -cne 'legacy-static-unwind-v1' -or $e.backend -cne 'rust/unicorn-x86' -or $e.architecture -cne $arch -or $e.api_calls -ne $expectedApis -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or $null -ne $e.kernel_threads -or $null -ne $e.kernel_ipi -or $null -ne $report.native_effect_failure){throw "Native-loader authority/profile/effect mismatch: $kind/$arch"}
  if($partial){
   if($exit -ne 1 -or $e.completion_reason -cne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error -or @($report.retired_images).Count -ne 0 -or $null -ne $report.preparation_error){throw 'Native-loader partial prefix fabricated completion/cleanup.'}
  }elseif($case.positive){
   $value=if($case.name -ceq 'root-dll'){1}else{42}
   if($exit -ne 0 -or $e.completion_reason -cne 'entry_return' -or $e.guest_entry_return -ne $value -or $null -ne $e.error -or @($report.events).Count -ne $case.events -or @($report.retired_images).Count -ne 0 -or $null -ne $report.preparation_error){throw "Actual native-loader guest initializer checks failed: $kind/$arch $($e.error)"}
   foreach($image in @($report.images)){if($image.lifecycle.phase -cne 'ready' -or -not $image.lifecycle.static_anchor){throw 'Mapped-only module was confused with actual completed initialization.'}}
   foreach($event in @($report.events)){if($null -eq $event.returned_value -or $null -ne $event.failure -or $event.invocation.arguments[1] -ne 1){throw 'Native-loader positive phase lacks an actual return.'};$reserved=if($event.invocation.routine -ceq 'dll_attach' -and $case.name -cne 'root-dll'){1}else{0};if($event.invocation.arguments[2] -ne $reserved){throw 'Native-loader attach reserved-value ABI mismatch.'}}
   if($case.name -in @('nested','forwarded')){$first=$report.events[0].invocation.module;$last=$report.events[-1].invocation.module;if(@($report.images|Where-Object {$_.id -eq $first -and $_.name -ceq 'other.dll'}).Count -ne 1 -or @($report.images|Where-Object {$_.id -eq $last -and $_.name -ceq 'guest.dll'}).Count -ne 1){throw 'Followed forwarded/dependency target must actually initialize before importer.'}}
  }else{
   $completion=if($case.budget){'instruction_budget'}else{'error'}
   if($exit -ne 1 -or $e.completion_reason -cne $completion -or $null -ne $e.guest_entry_return){throw "Native-loader negative fabricated completion: $kind/$arch"}
   if($case.prepare){if($e.instruction_count -ne 0 -or @($report.events).Count -ne 0 -or $null -eq $report.preparation_error -or @($report.retired_images).Count -ne 0){throw 'Refused startup executed an initializer or retired an untouched image.'}}
   else{if($null -ne $report.preparation_error -or @($report.events).Count -ne $case.events -or @($report.retired_images).Count -ne [int]$case.retired){throw 'Native-loader exact initialized/cleanup prefix mismatch.'}}
   if($case.budget){if($e.instruction_count -ne $budget -or $null -ne $e.error -or $null -ne $report.events[-1].returned_value -or $null -eq $report.events[-1].failure){throw 'Nonreturning initializer fabricated a return or reset the global budget.'}}
   elseif($case.error -and $e.error -notmatch [regex]::Escape($case.error)){throw "Native-loader wrong refusal: $kind/$arch $($e.error)"}
   if($case.ContainsKey('falseIndex')){if($report.events[$case.falseIndex].invocation.routine -cne 'dll_attach' -or $report.events[$case.falseIndex].returned_value -ne 0){throw 'Failed load lacks an actual DllMain FALSE result.'}}
   if($case.name -in @('false','nested-false','root-false')){foreach($event in @($report.events)){if($null -eq $event.returned_value -or $null -ne $event.failure){throw 'Completed failed-load cleanup includes an unfinished phase.'}};if($e.error -notmatch 'DllMain returned FALSE'){throw 'Wrong returned-FALSE outcome.'}}
   if($case.name -ceq 'root-false' -and $null -ne $report.primary){throw 'Actually unmapped failed primary retained a live primary identity.'}
   foreach($image in @($report.retired_images)){if($image.lifecycle.static_anchor -or @($e.loaded_modules|Where-Object {$_.name -ceq $image.name}).Count -ne 0){throw 'Retired static image retained a live anchor/catalog entry.'}}
  }
  foreach($event in @($report.events)){if($null -eq $event.stopped_instructions -or $event.stopped_instructions -lt $event.started_instructions -or $event.stopped_instructions -gt $e.instruction_count -or ($null -eq $event.returned_value -and $null -eq $event.failure)){throw 'Native-loader invocation evidence is not a real bounded execution prefix.'}}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;request_sha256=$requestHash;result_sha256=$resultHash;run=$run;reused=$reused}
  @{source_tree_sha256=$receipt.source_tree_sha256;status='in-progress';verified=$records.Count;records=$records}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'native-loader-verification.json') -Encoding utf8
 }
}}
if($records.Count -ne 62){throw 'Native-loader control count mismatch.'}
@{source_tree_sha256=$receipt.source_tree_sha256;status='passed';verified=$records.Count;records=$records}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'native-loader-verification.json') -Encoding utf8
$global:LASTEXITCODE=0
Write-Output '62 native-loader contained controls passed.'
