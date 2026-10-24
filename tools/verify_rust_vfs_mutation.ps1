param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing mutation evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='delete';names=0;bytes=0;artifacts=1;payloads=@('RUST')},@{name='unlink';names=1;bytes=4;artifacts=2;payloads=@('RUST','NEW!')},
 @{name='copy';names=2;bytes=8;artifacts=1;payloads=@('RUST')},@{name='copy-sharing';names=2;bytes=8;artifacts=1;payloads=@('RUST')},
 @{name='move';names=1;bytes=4;artifacts=2;payloads=@('RUST','TARG')},@{name='move-sharing';names=2;bytes=8;artifacts=2;payloads=@('RUST','TARG')},
 @{name='rename';names=1;bytes=4;artifacts=1;payloads=@('RUST')},@{name='rename-errors';names=1;bytes=4;artifacts=1;payloads=@('RUST')},@{name='failures';names=2;bytes=8;artifacts=2;payloads=@('RUST','TARG')},
 @{name='flags-unsupported';error='*MoveFileEx flags outside same-volume file profile*'},
 @{name='cross-volume-unsupported';error='*cross-volume file mutation is not modeled*'},
 @{name='directory-unsupported';error='*directory copy/move/delete is not modeled*'},
 @{name='root-unsupported';error='*FILE_RENAME_INFO RootDirectory handles are not modeled*'},
 @{name='class-unsupported';error='*SetFileInformationByHandle classes outside FileRenameInfo are not modeled*'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($encoding in @('a','w')){foreach($case in $cases){
 $kind='mutation-'+$case.name+'-'+$encoding
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing mutation instruction baseline.'};$budget=$baseline[0].instructions-1}else{$budget=6000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Mutation containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 2 -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or $null -eq $e.file_storage -or $null -eq $e.file_enumeration){throw "Mutation native/user/report mismatch $arch ${kind}."}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "Mutation explicit stop mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "Mutation prefix fabricated return $arch ${kind}."}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Mutation guest backing/bytes/sharing/poison/pointer checks failed $arch ${kind}: $($e.error)"}
  if(@($e.api_events|Where-Object {$_.api -notlike 'kernel32.*'}).Count){throw 'Mutation fixture module mismatch.'}
  if($e.console.stdout -ne '' -or $e.console.stderr -ne '' -or $e.console.raw_bytes -ne 0 -or $e.console.write_events.Count -ne 0){throw 'Mutation fabricated console output.'}
  $s=$e.file_storage
  if($s.scope -notlike '*legacy immediate unlink*' -or $s.unlinked_objects -ne 0 -or $s.unlinked_bytes -ne 0){throw 'Mutation profile or unnamed backing lifetime mismatch.'}
  if(-not $case.error){
   $events=@($e.api_events);if(@($events|Where-Object {$null -ne $_.error}).Count -or $events[-1].last_error -ne 0x12345678){throw 'Mutation positive contains API fault or wrong LastError.'}
   if($s.named_files -ne $case.names -or $s.named_bytes -ne $case.bytes -or $s.accounted_bytes -ne $case.bytes -or $s.open_handles -ne 0){throw 'Mutation actual named/unnamed storage or last-close accounting mismatch.'}
   if($e.file_enumeration.active.Count -ne 0 -or $e.file_enumeration.snapshot_bytes -ne 0 -or $e.file_enumeration.lifetime_handles -ne $(if($case.name -eq 'move'){1}else{0})){throw 'Mutation search metadata verification leaked handles.'}
   if($e.artifacts.Count -ne $case.artifacts){throw 'Mutation evidence count mismatch.'}
   $payloads=@()
   foreach($a in $e.artifacts){
    $file=Join-Path (Join-Path $run 'artifacts') $a.filename;$bytes=[IO.File]::ReadAllBytes($file);$payload=[Text.Encoding]::ASCII.GetString($bytes);$payloads+=$payload
    if($a.size -ne 4 -or $case.payloads -cnotcontains $payload -or (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant() -cne $a.sha256 -or $a.observations.Count -lt 1){throw 'Mutation actual evidence bytes/hash mismatch.'}
    foreach($o in $a.observations){if($o.kind -ne 'guest_file' -or $o.guest_path -notlike 'c:\workspace\*' -or $o.source -notin @('virtual_file_at_stop','virtual_file_delete','virtual_file_copy','virtual_file_move','virtual_file_move_replaced')){throw 'Mutation artifact provenance mismatch.'}}
   }
   foreach($payload in $case.payloads){if($payloads -cnotcontains $payload){throw 'Mutation expected evidence bytes missing.'}}
   if($case.name -in @('delete','unlink') -and @($e.artifacts.observations|Where-Object {$_.source -eq 'virtual_file_delete'}).Count -ne 1){throw 'Mutation delete evidence missing or duplicated.'}
   if($case.name -eq 'move' -and @($e.artifacts.observations|Where-Object {$_.source -eq 'virtual_file_move_replaced'}).Count -ne 1){throw 'Mutation replaced evidence missing or duplicated.'}
  }elseif($e.artifacts.Count -ne 0 -or $s.named_bytes -ne 0 -or $s.accounted_bytes -ne 0){throw 'Unsupported mutation invented byte artifacts.'}
  $records+=@{arch=$arch;encoding=$encoding;case=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;verified=$true}
 }
}}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 92){throw 'Mutation control count mismatch.'}
Write-Output "Verified $($records.Count) contained file copy/move/rename/legacy-unlink/backing/sharing/error/budget controls."
$global:LASTEXITCODE=0
