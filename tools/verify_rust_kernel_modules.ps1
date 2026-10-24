param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'assert_rust_default_kernel_metadata.ps1')
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing module evidence; choose fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(
 @{name='standard';calls=5},@{name='extended';calls=5},@{name='relocated-extended';calls=5},@{name='alias-standard';calls=5},@{name='alias-extended';calls=5},@{name='optional-length';calls=5},@{name='short';calls=4},@{name='pc-only';calls=3},
 @{name='read-only-output';calls=1;error='range'},@{name='read-only-length';calls=1;error='range'},@{name='unmapped-output';calls=1;error='range'},@{name='unmapped-length';calls=1;error='range'},@{name='null-output';calls=1;error='range'},
 @{name='overlap';calls=1;error='outputs overlap'},@{name='unknown-time';calls=1;error='outside the modeled 11/77 module profile'},@{name='unknown-debugger';calls=1;error='outside the modeled 11/77 module profile'},@{name='unknown-ci';calls=1;error='outside the modeled 11/77 module profile'},@{name='unknown-process';calls=1;error='outside the modeled 11/77 module profile'},
 @{name='high-irql';calls=2;error='requires supported PASSIVE_LEVEL'},@{name='missing-provenance';calls=2;error='lacks explicit guest path/header provenance'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-modules-'+$case.name;$negative=[bool]$case.error;$calls=$case.calls;$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing kernel-wait budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=10000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}));$reused=Test-Path -LiteralPath $run
  if($reused){if(-not $Resume){throw 'Never overwrite an existing generated module run.'}}
  else{& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultPath=Join-Path $run 'fixture-result.json';$resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Module run belongs to another frozen build.'}}
  if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -ne $kind -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget){throw 'Module request/result/build/cleanup binding failed.'}
  $e=$result.execution
  if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Module-query packaged offline containment failure.'}
  Assert-RustDefaultKernelMetadata -Execution $e -Architecture $arch
  $report=$e.kernel_modules
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $e.api_calls -ne $calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or $null -ne $e.kernel_threads -or $report.events_omitted -ne 0 -or $report.native_effect_failure -or @($e.loaded_modules).Count -ne 11){throw 'Module query native/API/catalog evidence mismatch.'}
  if($negative){
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error -or $null -ne $e.api_events[-1].result -or @($report.last_inventory).Count -ne 0){throw 'Rejected module query fabricated output or completion.'}
   if($case.name -eq 'missing-provenance'){if(@($report.events).Count -ne 1 -or $report.events[0].operation -ne 'pc_to_file_header' -or $report.events[0].found_base -eq 0){throw 'Missing provenance must permit genuine range lookup but refuse inventory.'}}
   elseif(@($report.events).Count -ne 0){throw 'Rejected query recorded a completed native output.'}
  }else{
   if($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Module-query budget prefix fabricated guest completion.'}}
   elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Guest module bytes/header/path/ABI checks failed: $($e.error)"}
   if(@($report.events).Count -ne $calls){throw 'Module completed-effect count mismatch.'}
   $pc=@($report.events|Where-Object {$_.operation -eq 'pc_to_file_header'})
   if($pc.Count -ne 3 -or $pc[0].found_base -eq 0 -or $pc[1].found_base -ne 0 -or $pc[2].found_base -eq 0){throw 'Half-open root/one-past/real-provider lookup proof failed.'}
   if($case.name -eq 'pc-only'){if(@($report.last_inventory).Count -ne 0){throw 'Lookup-only execution invented a queried inventory.'}}
   else{
    $rows=@($report.last_inventory);if($rows.Count -ne 11 -or ($rows.name -join ',') -cne 'ntoskrnl.exe,hal.dll,generated-fixture.exe,cng.sys,ci.dll,ntfs.sys,netio.sys,volmgr.sys,disk.sys,tcpip.sys,ndis.sys'){throw 'Real catalog insertion-priority ordering changed.'}
    foreach($row in $rows){$mapped=@($e.loaded_modules|Where-Object {$_.name -ceq $row.name -and [decimal]$_.base -eq [decimal]$row.base -and $_.size -eq $row.image_size});if($mapped.Count -ne 1 -or $row.provenance.accepted_image_sha256 -notmatch '^[0-9a-f]{64}$'){throw 'Module row lost actual mapping/accepted-byte provenance.'}}
    $expectedBase=if($arch -eq 'x64'){5368709120L}else{4194304L};$preferred=$expectedBase+$(if($case.name -eq 'relocated-extended'){2097152}else{0})
    if($rows[2].base -ne $expectedBase -or $rows[2].provenance.guest_path -cne 'C:\emumee\generated-fixture.exe' -or $rows[2].provenance.accepted_headers.timestamp -ne 0x12345678L -or $rows[2].provenance.accepted_headers.checksum -ne 0x98765432L -or $rows[2].provenance.accepted_headers.preferred_base -ne $preferred){throw 'Original accepted header metadata or declared owned path changed.'}
    $queries=@($report.events|Where-Object {$_.operation -eq 'system_information'});$expectedQueries=if($case.name -eq 'short'){1}else{2}
    if($queries.Count -ne $expectedQueries -or $queries[0].status -ne 0xc0000004L -or $queries[0].copied -ne 0){throw 'Required-length retry invented returned bytes.'}
    if($expectedQueries -eq 2 -and ($queries[1].status -ne 0 -or $queries[1].copied -ne $queries[0].required -or $queries[1].required -ne $queries[0].required)){throw 'Successful exact output length mismatch.'}
   }
  }
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;reused=[bool]$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 56){throw 'Module-query control count mismatch.'}
Write-Output "Verified $($records.Count) contained module layouts/paths/headers/real relocation, half-open lookups, unsupported classes/provenance, protected outputs and budget controls."
$global:LASTEXITCODE=0
