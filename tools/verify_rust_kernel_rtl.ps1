param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing RTL evidence; choose a fresh root.'}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
if($receipt.schema -ne 2){throw 'RTL frozen receipt schema mismatch.'}
foreach($binding in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
 $actual=(Get-FileHash -LiteralPath (Join-Path $bundlePath $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($receipt.($binding.key) -cne $actual){throw "RTL frozen binary differs from receipt: $($binding.file)."}
}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='strings'},@{name='init'},@{name='flags-empty';owned=1},@{name='counted';owned=1},@{name='invalid-descriptor'},@{name='overflow'},
 @{name='lifecycle';owned=1},@{name='generic-free';owned=1},@{name='format-secure';format=$true},@{name='format-secure-small';format=$true},
 @{name='format-list';format=$true},@{name='format-list-exact';format=$true},@{name='format-list-small';format=$true},
 @{name='borrowed-free';error='*actual live owned duplicate buffer*'},@{name='interior-free';error='*actual live owned duplicate buffer*';owned=1;live=1},
 @{name='stale-free';error='*actual live owned duplicate buffer*';owned=1},@{name='same-tag-reuse';error='*actual live owned duplicate buffer*';owned=1;other=1},
 @{name='readonly-output';error='*API guest range*'},@{name='cross-page-output';error='*API guest range*'},
 @{name='irql-duplicate';error='*duplication requires IRQL<=APC_LEVEL*'},@{name='irql-free';error='*release requires IRQL<=APC_LEVEL*';owned=1;live=1},
 @{name='irql-paged-read';error='*paged Pool access above APC_LEVEL*';owned=1;live=1},
 @{name='format-unsupported';error='*format conversion is not modeled*'},@{name='readonly-format';error='*API guest range*'},
 @{name='retired-read';error='*READ_UNMAPPED*';owned=1;rawfault=1},@{name='retired-execute';error='*FETCH_UNMAPPED*';owned=1;rawfault=1}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-rtl-'+$case.name;$negative=[bool]$case.error;$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -ceq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -ceq $arch -and $_.kind -ceq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'RTL actual instruction baseline missing.'};$budget=$baseline[0].instructions-1}else{$budget=20000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$resultPath=Join-Path $run 'fixture-result.json'
  $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($receipt.$key -cnotmatch '^[a-f0-9]{64}$' -or $manifest.$key -cne $receipt.$key){throw 'RTL run differs from frozen build receipt.'}}
  if($manifest.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -cne $kind -or $request.architecture -cne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000){throw 'RTL exact request/result/worker-exit/cleanup binding failed.'}
  $e=$result.execution;$r=$e.kernel_rtl;$pool=$e.kernel_pool
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'RTL packaged offline containment failure.'}
  if($e.backend -cne 'rust/unicorn-x86' -or $e.architecture -cne $arch -or $null -eq $r -or $null -eq $pool -or $null -eq $e.kernel_cpu -or ($e.kernel_cpu.current.cs -band 3) -ne 0 -or $null -ne $e.console -or $null -ne $e.crt_stdio -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or $e.api_events_omitted -ne 0){throw 'RTL actual backend/kernel/guest-only provenance mismatch.'}
  if($r.native_effect_failure -or $r.events_omitted -ne 0 -or $r.formatting_omitted -ne 0 -or $r.capture_errors -ne 0 -or $r.lifetime_limit -ne 4096){throw 'RTL bounded observer/terminal state mismatch.'}
  $owned=[int]$case.owned;$live=[int]$case.live;$other=[int]$case.other
  if($r.lifetime_allocations -ne $owned -or @($r.owned).Count -ne $owned -or $r.live_allocations -ne $live -or $pool.total_allocations -ne ($owned+$other) -or $pool.total_frees -ne ($owned-$live) -or @($pool.allocations.PSObject.Properties).Count -ne ($live+$other) -or $pool.mapped_bytes -ne ($live+$other)*4096){throw "RTL actual Pool ownership/generic retirement mismatch $arch ${kind}."}
  foreach($record in $r.owned){
   $requested=if($case.name -ceq 'flags-empty'){2}elseif($case.name -ceq 'counted'){8}else{10}
   if(-not $record.initialized -or [bool]$record.live -ne [bool]$live -or $record.requested -ne $requested -or $record.allocation_ordinal -ne 1 -or ($arch -ceq 'x64' -and [uint64]$record.base -le [uint32]::MaxValue)){throw 'RTL exact allocation provenance/fullwidth pointer mismatch.'}
  }
  if($negative){if($exit -ne 1 -or $e.completion_reason -cne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "RTL honest stop mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -cne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'RTL exact prefix fabricated entry completion.'}}
  elseif($exit -ne 0 -or $e.completion_reason -cne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "RTL guest bytes/counts/poison/ABI checks failed $arch ${kind}: $($e.error)"}
  $events=@($e.api_events)
  if(@($events|Where-Object {$_.last_error -ne 0x12345678 -or $_.thread_id -ne 1 -or $_.execution_domain -cne 'ordinary_thread'}).Count){throw "RTL changed actual caller LastError/context $arch ${kind}."}
  if(@($events|Where-Object {$_.api -notlike 'ntoskrnl.*' -and $_.api -notlike 'kernel32.*'}).Count){throw 'RTL fixture provider mismatch.'}
  if(-not $negative -or $case.rawfault){if(@($events|Where-Object {$null -ne $_.error}).Count){throw 'RTL successful API or later raw memory fault fabricated API failure.'}}
  if(-not $negative){$last=$events[-1];if($last.api -notlike '*.GetLastError' -or $last.result -ne 0x12345678){throw 'RTL actual GetLastError observation missing.'}}
  if($case.name -like 'irql-*'){if($e.kernel_state.irql -ne 2 -or ($arch -ceq 'x64' -and $e.cpu.cr8_writes -ne 1)){throw 'RTL did not observe actual processor IRQL instruction/state.'}}
  if(@($r.formatting).Count -ne [int][bool]$case.format){throw 'RTL format output capture count mismatch.'}
  if($case.format){
   $full='-464 4294967338 emu '+$(if($arch -ceq 'x64'){'0000000140000000'}else{'00400000'})
   $short=$case.name -like '*-small';$secure=$case.name -like 'format-secure*';$expectedResult=if($short){-1}else{$full.Length};$text=if($short){if($secure){''}else{'-46'}}else{$full}
   $raw=if($short -and $secure){[byte[]]@(0,0,52,0,54,0)}elseif($short){[Text.Encoding]::Unicode.GetBytes('-46')}else{[Text.Encoding]::Unicode.GetBytes($full)}
   $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant();$capture=@($r.formatting)[0]
   if($capture.api -cne $(if($secure){'swprintf_s'}else{'_vsnwprintf'}) -or $capture.result -ne $expectedResult -or $capture.text -cne $text -or $capture.captured_units -ne $raw.Length/2 -or $capture.raw_utf16_sha256 -cne $hash -or [bool]$capture.truncated -ne [bool]$short){throw "RTL actual bounded formatting capture/hash/result mismatch $arch ${kind}."}
  }
  if($case.name -in @('invalid-descriptor','overflow') -and (@($r.events).Count -ne 1 -or $r.events[0].status -ne 3221225485)){throw 'RTL invalid counted input did not return known native status before effects.'}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;owned_allocations=$owned;live_allocations=$live;pool_allocations=$pool.total_allocations;source_tree_sha256=$receipt.source_tree_sha256;request_sha256=$requestHash;result_sha256=$resultHash;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 78){throw 'RTL control count mismatch.'}
Write-Output "Verified $($records.Count) contained NTOS raw Unicode/Pool lifetime/CRT/ABI/formatting/preflight/IRQL/memory refusal/budget controls."
$global:LASTEXITCODE=0
