param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$VfsCurrentDirectory,[switch]$EnvironmentBlocks)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing persona evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='variable';last_error=998},@{name='mutation';last_error=0},@{name='expansion';last_error=0x12345678},
 @{name='directories';last_error=0},@{name='identity';last_error=0},@{name='command-line';last_error=998},
 @{name='command-free';error='*system-owned command-line storage*'},
 @{name='command-protect';error='*system-owned command-line storage*'},
 @{name='command-recommit';error='*system-owned command-line storage*'},
 @{name='blocks-unsupported';error=$(if($EnvironmentBlocks){'*system-owned environment-block storage*'}else{'*Environment-block allocation and free require guest ownership integration*'})},
 @{name='cwd-unsupported';error=$(if($VfsCurrentDirectory){'*drive-relative paths are not modeled*'}else{'*SetCurrentDirectory requires modeled VFS directory validation and commit*'})}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($encoding in @('a','w')){foreach($case in $cases){
 $kind='persona-'+$case.name+'-'+$encoding
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){
   $baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $kind -and -not $_.partial})
   if($baseline.Count -ne 1){throw 'Missing persona instruction baseline.'}
   $budget=$baseline[0].instructions-1
  }else{$budget=1000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Persona containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 2 -or $e.api_events_omitted -ne 0 -or $e.artifacts.Count -ne 0 -or $e.network.calls -ne 0){throw "Persona user/native/guest-only report mismatch $arch ${kind}."}
  if($case.error){
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "Persona explicit-stop mismatch $arch ${kind}: $($e.error)"}
  }elseif($partial){
   if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "Persona budget stop fabricated return $arch ${kind}."}
  }elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Persona guest byte/count/status/pointer checks failed $arch ${kind}: $($e.error)"}
  if(@($e.api_events|Where-Object {$_.api -notlike 'kernel32.*' -and $_.api -notlike 'advapi32.GetUserName*'}).Count){throw 'Persona fixture module mismatch.'}
  if(-not $case.error){
   if(@($e.api_events|Where-Object {$null -ne $_.error}).Count){throw 'Persona positive contains API error.'}
   $events=@($e.api_events);if($events.Count -eq 0 -or $events[-1].last_error -ne $case.last_error){throw "Persona final LastError mismatch $arch ${kind}."}
  }
  if($case.name -like 'command-*' -and $case.name -ne 'command-line'){
   if(-not @($e.api_events|Where-Object {$_.api -like 'kernel32.GetCommandLine*' -and $null -ne $_.result -and $_.result -ne 0}).Count){throw 'Persona guard did not first allocate a real guest command-line pointer.'}
  }
  $records+=@{arch=$arch;case=$kind;encoding=$encoding;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;verified=$true}
 }
}}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 68){throw 'Persona control count mismatch.'}
Write-Output "Verified $($records.Count) contained persona environment/encoding/identity/directory/command-line/ownership/budget controls."
$global:LASTEXITCODE=0
