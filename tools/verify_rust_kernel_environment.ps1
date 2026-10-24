param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'assert_rust_default_kernel_metadata.ps1')
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing environment evidence; choose a fresh root.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='kernel-environment-identity';calls=8;queries=8;writes=1},
 @{name='kernel-environment-null-output';calls=1;queries=1},
 @{name='kernel-environment-bad-output';calls=1;queries=1;error='lacks permission2'},
 @{name='kernel-environment-readonly-output';calls=1;queries=1;error='lacks permission2'},
 @{name='kernel-environment-cross-page-output';calls=1;queries=1;error='lacks permission2'},
 @{name='kernel-environment-limits';calls=2},
 @{name='kernel-environment-data-only';calls=0},
 @{name='kernel-environment-global-write';calls=0;error='WRITE_PROT'},
 @{name='kernel-environment-global-call';calls=0;error='FETCH_PROT'},
 @{name='kernel-environment-api-global-write';calls=1;error='Modeled kernel global READ/NX page'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $case.name -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing environment budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=1000}
  $run=Join-Path $root ($arch+'-'+$case.name+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $case.name --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution;$r=$e.kernel_environment
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Environment packaged offline worker containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $null -eq $r -or $e.api_calls -ne $case.calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0){throw "Environment native/kernel/offline report mismatch $arch $($case.name)."}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error){throw "Environment negative mismatch $arch $($case.name): $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Environment budget stop fabricated an entry return.'}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Environment guest ABI/data/topology checks failed $arch $($case.name): $($e.error)"}
  if($r.queries -ne [int]$case.queries -or $r.processor_number_writes -ne [int]$case.writes -or $r.identity.logical_processors -ne 12 -or $r.identity.current_processor -ne 0 -or $r.identity.windows_build -ne 22631 -or @($r.globals).Count -ne 5){throw 'Environment modeled topology/output state mismatch.'}
  $highest=if($arch -eq 'x64'){[uint64]0x7ffffffeffff}else{[uint64]0x7ffeffff}
  foreach($row in @($r.globals)){
   $width=if($row.name -in @('KeNumberProcessors','KdDebuggerEnabled','KdDebuggerNotPresent')){1}elseif($arch -eq 'x64'){8}else{4}
   $value=switch($row.name){'KeNumberProcessors'{12};'MmHighestUserAddress'{$highest};'MmUserProbeAddress'{$highest+1};'KdDebuggerEnabled'{0};'KdDebuggerNotPresent'{1};default{throw 'Unexpected modeled kernel global.'}}
   if($row.width -ne $width -or $row.value -ne $value -or $row.permissions -ne 'r--' -or $row.address -eq 0){throw 'Kernel typed global width/value/permissions mismatch.'}
  }
  Assert-RustDefaultKernelMetadata -Execution $e -Architecture $arch
  if(@($e.synthetic_providers).Count -ne 8){throw 'Kernel data import did not initialize owned providers.'}
  if($arch -eq 'x64'){$catalog=$e.synthetic_providers[0].reference_catalog;if($catalog.reference_code_symbols -ne 3180 -or $catalog.reference_data_symbols -ne 77 -or $catalog.protected_size -ne $catalog.protected_symbols*4096){throw 'Typed data provider lost reference classification or protected-page ownership.'}}
  if(@($e.api_events|Where-Object {$_.api -notlike 'ntoskrnl.*' -or $_.last_error -ne 0}).Count){throw 'Environment calls escaped guest kernel APIs or changed Win32 last error.'}
  $records+=@{arch=$arch;case=$case.name;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;verified=$true}
 }
}}
if($records.Count -ne 28){throw 'Environment control count mismatch.'}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained kernel environment topology/data/READ-NX/output-failure/budget controls."
$global:LASTEXITCODE=0
