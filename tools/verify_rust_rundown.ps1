param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing rundown evidence; choose a fresh root.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='rundown-lifecycle';calls=5;live=1;down=$true},
 @{name='rundown-free';calls=6},@{name='rundown-zero';calls=6},
 @{name='rundown-blocked-wait';calls=3;live=1;refs=3;down=$true;blocked=1;error='requires kernel thread scheduling'},
 @{name='rundown-blocked-free';calls=3;live=1;refs=3;blocked=1;error='requires kernel thread scheduling'},
 @{name='rundown-underflow';calls=3;live=1;refs=1;error='release exceeds acquired references'},
 @{name='rundown-invalid-pointer';calls=1;error='invalid cache-aware rundown reference'},
 @{name='rundown-double-free';calls=3;error='invalid cache-aware rundown reference'},
 @{name='rundown-pool-free';calls=2;live=1;error='bypass a live cache-aware rundown object'},
 @{name='rundown-body-read';calls=1;live=1;error='READ_PROT';denial=$true},
 @{name='rundown-body-write';calls=1;live=1;error='WRITE_PROT';denial=$true},
 @{name='rundown-body-call';calls=1;live=1;error='FETCH_PROT';denial=$true},
 @{name='rundown-api-read';calls=2;live=1;error='unmodeled private EX_RUNDOWN_REF_CACHE_AWARE';denial=$true},
 @{name='rundown-api-write';calls=2;live=1;error='unmodeled private EX_RUNDOWN_REF_CACHE_AWARE';denial=$true},
 @{name='rundown-irql-allocate';calls=2;error='allocation above APC_LEVEL'},
 @{name='rundown-irql-access';calls=3;live=1;error='access above DISPATCH_LEVEL'},
 @{name='rundown-irql-teardown';calls=3;live=1;error='teardown above APC_LEVEL'},
 @{name='rundown-unsupported-pool';calls=1;error='NX nonpaged pool types'},
 @{name='rundown-reenable';calls=3;live=1;down=$true;error='Unsupported Windows API|reinitialization.*not modeled'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $case.name -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing rundown budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=1000}
  $run=Join-Path $root ($arch+'-'+$case.name+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $case.name --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution;$r=$e.kernel_cache_aware_rundown
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Rundown packaged offline worker containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $null -eq $r -or $e.api_calls -ne $case.calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0){throw "Rundown native/kernel/opaque/offline report mismatch $arch $($case.name)."}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error){throw "Rundown negative mismatch $arch $($case.name): $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Rundown budget stop fabricated an entry return.'}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Rundown guest ABI/Boolean/lifetime checks failed $arch $($case.name): $($e.error)"}
  if(@($r.references).Count -ne [int]$case.live -or @($r.blocked_teardowns).Count -ne [int]$case.blocked -or $r.native_effect_failure -or @($e.kernel_pool.allocations.PSObject.Properties).Count -ne [int]$case.live){throw 'Rundown ownership/blocked teardown state mismatch.'}
  foreach($row in @($r.references)){
   if($row.references -ne [int]$case.refs -or [bool]$row.running_down -ne [bool]$case.down -or $row.permissions -ne '---' -or $row.logical_cpus -lt 1 -or $row.logical_cpus -gt 64 -or $row.size -ne 64*($row.logical_cpus+1) -or $row.mapped -ne [math]::Ceiling($row.size/4096.0)*4096 -or $row.pool_type -ne 0x600){throw 'Rundown guest reference/topology/opaque reservation mismatch.'}
  }
  if($case.denial -and @($r.api_denials).Count -eq 0){throw 'Private rundown body access lacked denial evidence.'}
  if($case.blocked){$blocked=$r.blocked_teardowns[0];$operation=if($case.name -eq 'rundown-blocked-wait'){'Wait'}else{'Free'};if($blocked.operation -ne $operation -or $blocked.references -ne 3){throw 'Blocked rundown teardown fabricated completion or changed holder counts.'}}
  if(@($e.api_events|Where-Object {$_.api -notlike 'ntoskrnl.*' -or $_.last_error -ne 0}).Count){throw 'Rundown calls escaped guest kernel APIs or changed Win32 last error.'}
  $records+=@{arch=$arch;case=$case.name;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;verified=$true}
 }
}}
if($records.Count -ne 44){throw 'Rundown control count mismatch.'}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained rundown Fastcall/reference/opaque-lifetime/IRQL/blocking/budget controls."
$global:LASTEXITCODE=0
