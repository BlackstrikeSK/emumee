param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing thread evidence; choose fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(@{name='lifecycle'},@{name='extended'},@{name='self-modify'},@{name='invalid';error='MOV CR8 value has reserved bits'},@{name='user-mode';error='MOV CR8 requires an initialized CPL0 driver'})
$records=@()
foreach($arch in @('x64')){foreach($case in $cases){
 $kind='kernel-cr8-'+$case.name;$negative=[bool]$case.error;$calls=if($negative){0}else{2};$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing kernel-wait budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=10000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}));$reused=Test-Path -LiteralPath $run
  if($reused){if(-not $Resume){throw 'Never overwrite an existing generated thread run.'}}
  else{& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultPath=Join-Path $run 'fixture-result.json';$resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Thread run belongs to another frozen build.'}}
  if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -ne $kind -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget){throw 'Thread request/result/build/cleanup binding failed.'}
  $e=$result.execution
  if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'CR8 packaged offline containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne 'x64' -or $e.api_calls -ne $calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0){throw 'CR8 native/API evidence mismatch.'}
  if($negative){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error -or $e.cpu.cr8_writes -ne 0 -or $e.cpu.cr8_reads -ne 0){throw 'Invalid CR8 instruction/context changed state or invented entry success.'};if($null -ne $e.kernel_cpu -and ($e.kernel_cpu.pcr_irql -ne 0 -or $e.kernel_state.irql -ne 0)){throw 'Rejected CR8 changed owned IRQL state.'}}
  else{
   if($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'CR8 budget prefix fabricated guest completion.'}}
   elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "CR8 guest flags/GPR/IRQL/selfmod checks failed: $($e.error)"}
   if($e.cpu.cr8_writes -ne 2 -or $e.cpu.cr8_reads -lt 2 -or $e.kernel_cpu.pcr_irql -ne 0 -or $e.kernel_state.irql -ne 0 -or $e.api_events[0].result -ne 13 -or $e.api_events[1].result -ne 0){throw 'CR8 actual instructions, PCR and API views disagree.'}
  }
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;reused=[bool]$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 8){throw 'CR8 control count mismatch.'}
Write-Output "Verified $($records.Count) contained actual MOV CR8 operand, flags/GPR/PCR/API, selfmodification, refusal and budget controls."
$global:LASTEXITCODE=0
