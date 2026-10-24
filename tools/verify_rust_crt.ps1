param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$CopyControls)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing CRT evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='crt-memory'},@{name='crt-strings'},@{name='crt-wide'},@{name='crt-boundary'},@{name='crt-rewrite'},
 @{name='crt-read-fault';error='*lacks permission*'},@{name='crt-write-fault';error='*lacks permission*'},
 @{name='crt-overlap';error='*overlapping*'},@{name='crt-overflow';error='*CRT transfer count*'}
)
$records=@()
if($CopyControls){$cases+=@(@{name='crt-copy'},@{name='crt-string-overlap';error='*overlapping*'},@{name='crt-copy-invalid';error='*invalid-parameter*'})}
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $budgets=@(1000)
 if(-not $case.error){$budgets+='before-return'}
 foreach($mode in $budgets){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $case.name -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing CRT budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=1000}
  $run=Join-Path $root ($arch+'-'+$case.name+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $case.name --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json;$e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'CRT containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 1 -or $e.api_events_omitted -ne 0 -or $e.artifacts.Count -ne 0 -or $e.network.calls -ne 0){throw 'CRT native/user/guest-only report mismatch.'}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "CRT negative mismatch $arch $($case.name): $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'CRT budget stop fabricated entry return.'}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "CRT guest byte/pointer/Cdecl checks failed $arch $($case.name): $($e.error)"}
  $module=if($case.name -eq 'crt-strings'){'ucrtbase'}elseif($case.name -eq 'crt-wide'){'api-ms-win-crt-string-l1-1-0'}else{'msvcrt'}
  if(@($e.api_events|Where-Object {$_.api -notlike ($module+'.*') -or $_.last_error -ne 0}).Count){throw 'CRT module alias or Win32 last-error preservation changed.'}
  if($arch -eq 'x64' -and $case.name -in @('crt-memory','crt-wide','crt-rewrite') -and -not @($e.api_events|Where-Object {$_.api -match '\.(w?memcpy|w?memmove|w?memset)$' -and $_.result -gt 0xffffffffL}).Count){throw 'CRT pointer result lost its high32 bits.'}
  $records+=@{arch=$arch;case=$case.name;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;verified=$true}
 }
}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained CRT Cdecl/byte/code-unit/page/rewrite/budget controls."
$global:LASTEXITCODE=0
