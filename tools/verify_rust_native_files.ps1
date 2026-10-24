param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve native-file evidence; select a fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'Native-file frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "Native-file frozen binary mismatch: $($binding.file)."}
}
$cases=@(
 @{name='basic';issues=1;events=6;calls=6},@{name='supersede';issues=2;events=6;calls=6},@{name='create-collision';issues=1;events=4;calls=4},@{name='overwrite';issues=2;events=6;calls=6},@{name='overwrite-if';issues=2;events=6;calls=6},@{name='open-existing';issues=2;events=6;calls=6},
 @{name='directory';issues=2;events=6;calls=6},@{name='offsets';issues=1;events=9;calls=9},@{name='sharing';issues=1;events=3;calls=4},@{name='typed-close';issues=1;events=3;calls=3},@{name='readonly';issues=2;events=5;calls=5},@{name='missing';issues=0;events=2;calls=2},@{name='unlink';issues=1;events=6;calls=7},@{name='seed-read';issues=1;events=3;calls=3},@{name='seed-write';issues=1;events=4;calls=4},@{name='user-coherence';issues=1;events=3;calls=6},@{name='bounds';issues=1;events=4;calls=4},
 @{name='async';error='asynchronous native files'},@{name='event';error='event/APC/key asynchronous';opened=$true},@{name='apc';error='event/APC/key asynchronous';opened=$true},@{name='key';error='event/APC/key asynchronous';opened=$true},@{name='ea';error='EA/type/options/context unsupported'},@{name='security';error='object attributes/security unsupported'},@{name='context';error='EA/type/options/context unsupported'},@{name='bad-length';error='UNICODE_STRING length'},@{name='odd-unicode';error='strict UTF-16'},@{name='readonly-handle';error='range'},@{name='readonly-iosb';error='range'},@{name='readonly-read';error='range';opened=$true},@{name='overlap';error='outputs overlap'},@{name='cross-boundary';error='range'},@{name='high-irql';error='Native files require PASSIVE_LEVEL'},@{name='file-reference';error='Foreign process/file kernel handle reference profile'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='native-files-'+$case.name;$negative=[bool]$case.error;$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing native-file budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=10000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}));$reused=Test-Path -LiteralPath $run
  if(-not $reused){& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}elseif(-not $Resume){throw 'Never overwrite existing native-file run.'}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultPath=Join-Path $run 'fixture-result.json';$resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Native-file run belongs to another frozen build.'}}
  if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -ne $kind -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget){throw 'Native-file request/result/build/cleanup binding failed.'}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Native-file packaged offline containment failure.'}
  $e=$result.execution;$report=$e.kernel_files;if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if($null -eq $report -or $e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or $null -ne $e.kernel_threads -or $report.events_omitted -ne 0 -or $report.native_effect_failure -or -not $e.configuration.initialized -or -not $e.configuration.generated_only){throw 'Native-file authoritative configuration/effect evidence mismatch.'}
  if($negative){
   $expected=[int][bool]$case.opened
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch [regex]::Escape($case.error) -or $null -ne $e.api_events[-1].result -or $e.api_calls -ne (1+$expected) -or $report.handles.lifetime_issues -ne $expected -or @($report.handles.live).Count -ne $expected -or @($report.events).Count -ne $expected){throw "Rejected native-file profile fabricated completion/state: $kind/$arch"}
   foreach($live in @($report.handles.live)){if($live.position -ne 0 -or $live.unlinked -or $live.configured_backing){throw 'Rejected transfer changed backing identity/cursor.'}}
  }else{
   $extra=[int]($arch -eq 'x64' -and $case.name -eq 'typed-close')
   if($report.handles.lifetime_issues -ne $case.issues -or @($report.handles.live).Count -ne 0 -or @($report.events).Count -ne ($case.events+$extra) -or $e.api_calls -ne ($case.calls+$extra)){throw "Native-file actual typed lifetime/call evidence mismatch: $kind/$arch"}
   if($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Native-file budget prefix fabricated guest completion.'}}
   elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Guest native-file bytes/IOSB/ABI checks failed: $($e.error)"}
   if($case.name -eq 'missing'){if($report.events[0].status -ne 0xc0000034L -or $report.events[1].status -ne 0xc000003aL -or $report.events[0].information -ne 5 -or $report.events[1].information -ne 5){throw 'Missing final/parent status distinction changed.'}}
   if($case.name -eq 'user-coherence'){if(@($e.api_events|Where-Object {$_.api -like '*WriteFile' -and $_.result -eq 1}).Count -ne 1 -or @($report.events|Where-Object {$_.operation -eq 'read' -and $_.information -eq 4}).Count -ne 1){throw 'Win32/native bytes must share the actual sole backing.'}}
   if($case.name -in @('seed-read','missing') -and @($e.artifacts).Count -ne 0){throw 'Unchanged seed/absent file invented an artifact.'}
   if($case.name -eq 'seed-write'){
    if($report.events[0].information -ne 1 -or @($report.events|Where-Object {$_.operation -eq 'write' -and $_.information -eq 4}).Count -ne 1 -or @($report.events|Where-Object {$_.operation -eq 'read' -and $_.information -eq 4}).Count -ne 1){throw 'Native seed write/read must use the guest-owned VFS copy.'}
   }
   if($case.name -eq 'unlink'){
    $deleted=@($e.artifacts)
    if($deleted.Count -ne 1 -or $deleted[0].size -ne 4 -or $deleted[0].sha256 -cne '9d52b3111e77c4d8d696798aaa00bce14ec4aa384cd4080aaf0c8fe13294c3cf' -or @($deleted[0].observations).Count -ne 1 -or $deleted[0].observations[0].kind -ne 'guest_file' -or $deleted[0].observations[0].source -ne 'virtual_file_delete' -or $deleted[0].observations[0].guest_path -cne 'c:\users\morgan\downloads\nt-file.bin'){throw 'Unlink must preserve only the real pre-delete RUST snapshot with its historical Win32 deletion provenance.'}
   }
  }
  $records+=@{verified=$true;arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;api_calls=$e.api_calls;completion=$e.completion_reason;request_sha256=$requestHash;result_sha256=$resultHash;run=$run;reused=$reused}
  @{source_tree_sha256=$receipt.source_tree_sha256;status='in-progress';verified=$records.Count;records=$records}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'native-files-verification.json') -Encoding utf8
 }
}}
if($records.Count -ne 100){throw 'Native-file control count mismatch.'}
@{source_tree_sha256=$receipt.source_tree_sha256;status='passed';verified=$records.Count;records=$records}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'native-files-verification.json') -Encoding utf8
@{schema=1;source_tree_sha256=$receipt.source_tree_sha256;verified=$true;count=$records.Count;expected_count=100;records=$records}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8
$global:LASTEXITCODE=0
Write-Output '100 native-file contained controls passed.'
