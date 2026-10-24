param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing VFS metadata evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='directory';searches=0},@{name='metadata';searches=0;artifact=$true},@{name='enumeration';searches=1;artifact=$true},
 @{name='snapshot';searches=1},@{name='retry';searches=1},@{name='wildcard';searches=2},@{name='current-directory';searches=0},
 @{name='paths';searches=0},@{name='missing';searches=0},@{name='read-only';searches=0;artifact=$true},@{name='typed-handles';searches=2},
 @{name='attributes-unsupported';error='*file attributes outside modeled mutable profile*'},
 @{name='mask-unsupported';error='*search grammar or short-name matching is not modeled*'},
 @{name='security-unsupported';error='*Directory security attributes are not modeled*'},
 @{name='short-name-unsupported';error='*short-name expansion is not modeled*'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($encoding in @('a','w')){foreach($case in $cases){
 $kind='vfs-'+$case.name+'-'+$encoding
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing VFS metadata instruction baseline.'};$budget=$baseline[0].instructions-1}else{$budget=5000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'VFS metadata containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 2 -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or $null -eq $e.file_enumeration){throw "VFS metadata native/user/report mismatch $arch ${kind}."}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "VFS metadata explicit stop mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "VFS metadata prefix fabricated return $arch ${kind}."}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "VFS metadata guest catalog/bytes/count/poison/pointer checks failed $arch ${kind}: $($e.error)"}
  if(@($e.api_events|Where-Object {$_.api -notlike 'kernel32.*'}).Count){throw 'VFS metadata fixture module mismatch.'}
  if($e.console.stdout -ne '' -or $e.console.stderr -ne '' -or $e.console.raw_bytes -ne 0 -or $e.console.write_events.Count -ne 0){throw 'VFS metadata fabricated console output.'}
  if(-not $case.error){
   $events=@($e.api_events);if(@($events|Where-Object {$null -ne $_.error}).Count -or $events[-1].last_error -ne 0x12345678){throw 'VFS metadata positive contains API fault or wrong final LastError.'}
   if($e.file_enumeration.active.Count -ne 0 -or $e.file_enumeration.snapshot_bytes -ne 0 -or $e.file_enumeration.lifetime_handles -ne $case.searches){throw 'VFS search lifetime/cleanup/cursor publication mismatch.'}
  }elseif($e.file_enumeration.lifetime_handles -ne 0 -or $e.file_enumeration.active.Count -ne 0){throw 'Unsupported VFS profile allocated fabricated search state.'}
  if($case.artifact){
   if($e.artifacts.Count -ne 1){throw 'Actual guest RUST file artifact missing.'};$a=$e.artifacts[0];$file=Join-Path (Join-Path $run 'artifacts') $a.filename;$bytes=[IO.File]::ReadAllBytes($file)
   if([Text.Encoding]::ASCII.GetString($bytes) -cne 'RUST' -or $a.size -ne 4 -or (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant() -cne $a.sha256 -or $a.observations.Count -ne 1 -or $a.observations[0].kind -ne 'guest_file' -or $a.observations[0].guest_path -cne "c:\workspace\probe\caf$([char]0xe9).txt"){throw 'VFS metadata artifact bytes/canonical path/provenance mismatch.'}
  }elseif($e.artifacts.Count -ne 0){throw 'VFS metadata invented file artifacts.'}
  $records+=@{arch=$arch;encoding=$encoding;case=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;verified=$true}
 }
}}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 104){throw 'VFS metadata control count mismatch.'}
Write-Output "Verified $($records.Count) contained VFS directory/catalog/metadata/enumeration/path/CWD/error/budget controls."
$global:LASTEXITCODE=0
