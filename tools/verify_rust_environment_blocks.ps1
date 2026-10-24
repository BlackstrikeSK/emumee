param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing environment-block evidence; use explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $exe) 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(
 @{name='snapshot';allocations=2;live=0},@{name='empty';allocations=1;live=0},@{name='free-errors';allocations=1;live=0},
 @{name='quota';allocations=64;live=0},@{name='live';allocations=1;live=1},@{name='retired-reallocation';allocations=1;live=0},
 @{name='write';error='*WRITE_PROT*';live=1},@{name='protect';error='*system-owned environment-block storage*';live=1},
 @{name='free';error='*system-owned environment-block storage*';live=1},@{name='recommit';error='*system-owned environment-block storage*';live=1},
 @{name='retired-read';error='*READ_UNMAPPED*';live=0},@{name='retired-execute';error='*FETCH_UNMAPPED*';live=0}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($encoding in @('a','w')){foreach($case in $cases){
 $kind='environment-block-'+$case.name+'-'+$encoding
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing environment-block instruction baseline.'};$budget=$baseline[0].instructions-1}else{$budget=10000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  $reused=$false
  if(Test-Path -LiteralPath $run){
   if(-not $Resume){throw 'Refuse to overwrite existing environment run.'}
   $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
   $requestPath=Join-Path $run 'request.json';$resultPath=Join-Path $run 'fixture-result.json'
   $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
   $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
   $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
   $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
   foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Environment resume frozen build mismatch.'}}
   if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $request.kind -cne $kind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000){throw 'Environment resume request/result/cleanup binding failed.'}
   $saved=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
   if($saved.request_sha256 -cne $requestHash){throw 'Environment resume result request hash changed.'}
   $exit=if($saved.execution.completion_reason -eq 'entry_return'){0}else{1};$reused=$true
  }else{
   & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
   $exit=$LASTEXITCODE
  }
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Environment-block containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 26 -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or $e.artifacts.Count -ne 0 -or $null -eq $e.environment_blocks){throw "Environment-block native/user/report mismatch $arch ${kind}."}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "Environment-block real fault mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "Environment-block prefix fabricated return $arch ${kind}."}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Environment-block snapshot/bytes/free/poison/pointer checks failed $arch ${kind}: $($e.error)"}
  if(@($e.api_events|Where-Object {$_.api -notlike 'kernel32.*'}).Count){throw 'Environment-block fixture module mismatch.'}
  if($e.console.stdout -ne '' -or $e.console.stderr -ne '' -or $e.console.raw_bytes -ne 0 -or $e.console.write_events.Count -ne 0){throw 'Environment-block fabricated console output.'}
  $blocks=$e.environment_blocks;$expectedEncoding=if($encoding -eq 'a'){'Cp437'}else{'Utf16'}
  if($blocks.scope -notlike '*current guest process1024 only*' -or $blocks.scope -notlike '*READ pages*' -or $blocks.events_omitted -ne 0 -or $blocks.live.Count -ne $case.live -or $blocks.mapped_bytes -ne $case.live*4096){throw 'Environment-block live ownership/mapped quota/profile mismatch.'}
  foreach($item in $blocks.live){if($item.owner -ne 1024 -or -not $item.initialized -or $item.size -ne 4096 -or $item.encoding -cne $expectedEncoding){throw 'Environment-block invalid live ownership/backing metadata.'}}
  foreach($item in $blocks.events){if($item.owner -ne 1024 -or $item.encoding -cne $expectedEncoding -or $item.operation -notin @('allocated','freed') -or $item.address -le 0 -or ($arch -eq 'x64' -and $item.address -le [uint32]::MaxValue)){throw 'Environment-block encoding/full-width address/provenance mismatch.'}}
  if(-not $case.error){
   $events=@($e.api_events);if(@($events|Where-Object {$null -ne $_.error}).Count -or $events[-1].last_error -ne 0x12345678){throw 'Environment-block positive contains API fault or wrong LastError.'}
   if($blocks.lifetime_allocations -ne $case.allocations -or $blocks.events.Count -ne ($case.allocations*2-$case.live)){throw 'Environment-block allocation/free evidence mismatch.'}
   $allocated=@($blocks.events|Where-Object {$_.operation -eq 'allocated'})
   if(@($allocated|ForEach-Object {$_.address}|Sort-Object -Unique).Count -ne $case.allocations){throw 'Environment allocator reissued a retired address.'}
   for($i=0;$i -lt $allocated.Count;$i++){
    $size=if($case.name -eq 'empty'){if($encoding -eq 'a'){2}else{4}}elseif($case.name -eq 'snapshot' -and $i -eq 1){if($encoding -eq 'a'){15}else{30}}else{if($encoding -eq 'a'){10}else{22}}
    if($allocated[$i].bytes -ne $size){throw 'Environment block actual OEM/UTF16/double-NUL byte size mismatch.'}
   }
   if($case.name -eq 'quota' -and @($e.api_events|Where-Object {$_.api -like 'kernel32.GetEnvironmentStrings*' -and $_.result -eq 0 -and $_.last_error -eq 8}).Count -ne 1){throw 'Environment-block quota did not return honest NULL/8.'}
  }elseif($blocks.lifetime_allocations -ne 1 -or $blocks.events.Count -ne $(if($case.live){1}else{2})){throw 'Environment-block fault fabricated allocation or free evidence.'}
  $records+=@{arch=$arch;encoding=$encoding;case=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;reused_generated_run=$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 72){throw 'Environment-block control count mismatch.'}
Write-Output "Verified $($records.Count) contained owned environment snapshot/free/OEM/UTF16/lifetime/protection/error/budget controls."
$global:LASTEXITCODE=0
