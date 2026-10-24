param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing native registry evidence; select a fresh root.'}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'Native registry frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "Native registry frozen binary mismatch: $($binding.file)."}
}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='basic'},@{name='full'},@{name='retry'},@{name='relative'},@{name='roots'},@{name='missing'},
 @{name='rights'},@{name='typed-close'},@{name='default'},@{name='counted'},@{name='sid'},@{name='invalid-class'},@{name='truncated'},
 @{name='class-unsupported';error='*valid native value information class is not modeled*';live=1},
 @{name='attributes-unsupported';error='*Native registry object attributes/security profile unsupported*';live=0},
 @{name='bad-output';error='*API guest range*';live=0},
 @{name='query-readonly';error='*API guest range*';live=1},
 @{name='output-overlap';error='*Overlapping native registry outputs are not modeled*';live=1},
 @{name='irql-open';error='*Native registry/handle API requires PASSIVE_LEVEL*';live=0},
 @{name='irql-query';error='*Native registry/handle API requires PASSIVE_LEVEL*';live=1},
 @{name='irql-close';error='*Native registry/handle API requires PASSIVE_LEVEL*';live=1}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='native-registry-'+$case.name;$negative=[bool]$case.error;$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -ceq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -ceq $arch -and $_.kind -ceq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Native registry exact budget baseline missing.'};$budget=$baseline[0].instructions-1}else{$budget=20000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$resultPath=Join-Path $run 'fixture-result.json'
  $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($receipt.$key -cnotmatch '^[a-f0-9]{64}$' -or $manifest.$key -cne $receipt.$key){throw 'Native registry run differs from frozen receipt.'}}
  if($manifest.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -cne $kind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000){throw 'Native registry exact request/result/worker-exit/cleanup binding failed.'}
  $e=$result.execution;$r=$e.kernel_registry;$c=$e.configuration
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Native registry packaged offline containment failure.'}
  if($e.backend -cne 'rust/unicorn-x86' -or $e.architecture -cne $arch -or $null -eq $r -or $null -eq $c -or -not $c.initialized -or -not $c.generated_only -or $c.seeded_registry_keys -ne 4 -or $c.seeded_files -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or $e.api_events_omitted -ne 0){throw 'Native registry actual authority/configuration/API provenance mismatch.'}
  if($r.events_omitted -ne 0 -or $r.native_effect_failure -or $r.handles.lifetime_limit -ne 40000 -or $r.handles.omitted_handles -ne 0){throw 'Native registry bounded event/handle/effect evidence mismatch.'}
  if($negative){
   if($exit -ne 1 -or $e.completion_reason -cne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error -or $r.handles.live -ne $case.live -or $r.handles.lifetime_issues -ne $case.live){throw "Native registry honest stop/preflight mismatch $arch ${kind}: $($e.error)"}
   if($case.name -like 'irql-*'){
    if($e.kernel_state.irql -ne 2 -or @($r.events).Count -ne $case.live -or @($r.events|Where-Object {$_.operation -cne 'open'}).Count -or ($arch -ceq 'x64' -and $e.cpu.cr8_writes -ne 1)){throw 'Native registry accepted actual elevated processor IRQL or changed registry state.'}
   }
  }else{
   if($partial){if($exit -ne 1 -or $e.completion_reason -cne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Native registry exact prefix fabricated entry completion.'}}
   elseif($exit -ne 0 -or $e.completion_reason -cne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Native registry guest bytes/status/counts/poison checks failed $arch ${kind}: $($e.error)"}
   if($r.handles.live -ne 0 -or @($e.api_events|Where-Object {$null -ne $_.error}).Count){throw 'Native registry positive leaked a real handle or API fault.'}
   if($case.name -ceq 'retry'){
    $queries=@($r.events|Where-Object {$_.operation -ceq 'query'})
    if($queries.Count -ne 5 -or (($queries|ForEach-Object {$_.status}) -join ',') -cne '3221225507,3221225507,2147483653,2147483653,0' -or (($queries|ForEach-Object {$_.copied}) -join ',') -cne '0,0,12,14,16' -or @($queries|Where-Object {$_.required -ne 16}).Count){throw 'Native registry partial/no-output retry plan mismatch.'}
   }
   if($case.name -ceq 'typed-close' -and ($e.kernel_threads.count -ne 2 -or $e.kernel_threads.open_thread_handles -ne 0 -or @($r.events|Where-Object {$_.operation -ceq 'query' -and $_.status -eq 3221225508}).Count -ne 1)){throw 'Native registry/thread handle type/close lifetime mismatch.'}
  }
  foreach($row in @($r.events|Where-Object {$_.operation -ceq 'open' -and $_.status -eq 0})){
   if($row.handle -le 0 -or ($arch -ceq 'x64' -and [uint64]$row.handle -le [uint32]::MaxValue) -or ($arch -ceq 'x86' -and [uint64]$row.handle -gt [uint32]::MaxValue)){throw 'Native registry handle width/identity truncated.'}
   if($row.name_utf8_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $row.name_preview.Length -gt 128){throw 'Native registry bounded name provenance missing.'}
  }
  # LastError is per actual thread. TypedClose can drain its fresh child
  # after root GetLastError/return; that child's initial LastError is0.
  $events=@($e.api_events);$rootEvents=@($events|Where-Object {$_.thread_id -eq 1 -and $_.execution_domain -ceq 'ordinary_thread'})
  if($rootEvents.Count -eq 0 -or @($rootEvents|Where-Object {$_.last_error -ne 0x12345678}).Count){throw "Native registry changed actual root LastError $arch ${kind}."}
  $rootGet=@($rootEvents|Where-Object {$_.api -like '*.GetLastError'})
  if($rootGet.Count -ne $(if($negative){0}else{1}) -or @($rootGet|Where-Object {$_.result -ne 0x12345678}).Count){throw "Native registry actual root GetLastError result mismatch $arch ${kind}."}
  foreach($child in @($events|Where-Object {$_.thread_id -ne 1})){if($case.name -cne 'typed-close' -or $child.execution_domain -cne 'ordinary_thread' -or $child.last_error -ne 0){throw "Native registry child LastError/context mismatch $arch ${kind}."}}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;live_handles=$r.handles.live;lifetime_issues=$r.handles.lifetime_issues;source_tree_sha256=$receipt.source_tree_sha256;request_sha256=$requestHash;result_sha256=$resultHash;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 68){throw 'Native registry control count mismatch.'}
Write-Output "Verified $($records.Count) contained read-only native registry counted-name/query-prefix/status/rights/typed-lifetime/preflight/budget controls."
$global:LASTEXITCODE=0
