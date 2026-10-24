param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing TID proof; choose a fresh root or explicit Resume.'}}else{New-Item -ItemType Directory -Path $root|Out-Null}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
foreach($pair in @(@('emumee-rs.exe','controller_sha256'),@('emumee-worker.exe','worker_sha256'),@('unicorn.dll','unicorn_sha256'))){
 if((Get-FileHash -LiteralPath (Join-Path $bundlePath $pair[0]) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receipt.($pair[1])){throw 'Frozen TID binary hash mismatch.'}
}
$records=@();$exe=Join-Path $bundlePath 'emumee-rs.exe'
foreach($arch in @('x86','x64')){
 $fullCount=0
 foreach($partial in @($false,$true)){
  $budget=if($partial){$fullCount-1}else{10000}
  $run=Join-Path $root ($arch+$(if($partial){'-partial'}else{'-full'}))
  $reused=Test-Path -LiteralPath $run
  if(-not $reused){& $exe fixture --kind kernel-guest-tid --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}elseif(-not $Resume){throw 'Never overwrite TID evidence.'}else{$exit=$null}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $resultPath=Join-Path $run 'fixture-result.json';$result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  $stop=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'TID run source/build mismatch.'}}
  if($request.kind -ne 'kernel-guest-tid' -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget -or $request.iterations -ne 1000000 -or $manifest.request_sha256 -cne $requestHash -or $result.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $manifest.cleanup -ne 'restored' -or $stop.cleanup -ne 'restored' -or $stop.exit_code -ne 0){throw 'TID request/result/cleanup binding failed.'}
  $c=$result.containment;$e=$result.execution
  if(-not $c.app_container -or -not $c.job_object -or -not $c.child_process_blocked -or $c.network_capabilities -ne 0 -or $e.network.calls -ne 0 -or $e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.error -or $e.api_events_omitted -ne 0 -or $e.kernel_thread_objects.native_effect_failure -or $e.kernel_ipi.native_effect_failure){throw 'TID contained engine evidence invalid.'}
  if($reused){$savedConsole=Get-Content -LiteralPath ($run+'.console.log') -Raw|ConvertFrom-Json;if(($savedConsole|ConvertTo-Json -Depth 100 -Compress) -cne ($manifest|ConvertTo-Json -Depth 100 -Compress)){throw 'Saved TID stdout differs from final manifest.'}}
  if($partial){if((-not $reused -and $exit -ne 1) -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return){throw 'TID budget prefix invented completion.'}}
  else{if((-not $reused -and $exit -ne 0) -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17){throw 'Actual guest TID/CLIENT_ID assertions failed.'};$fullCount=$e.instruction_count}
  $lives=@($e.kernel_thread_objects.threads)
  $ids=@($lives|ForEach-Object {$_.guest_id}|Sort-Object -Unique)
  if($ids.Count -ne $lives.Count -or @($lives|Where-Object {$_.slot -eq 2 -and $_.guest_id -eq 0x1008 -and $_.terminated -and $_.retired -and $_.open_handles -eq 0}).Count -ne 1){throw 'Created/borrowed TID lifetime distinction failed.'}
  $calls=@($e.api_events|Where-Object {$_.api -eq 'ntoskrnl.PsGetCurrentThreadId'})
  if($calls.Count -ne 15){throw 'Expected root, child and12 real IPI identity observations.'}
  foreach($event in $calls){$life=@($lives|Where-Object {$_.address -eq $event.current_thread});if($life.Count -ne 1 -or $event.result -ne $life[0].guest_id -or $event.result -eq 0 -or $event.last_error -ne 0 -or $event.pending -or $null -ne $event.error){throw 'API TID does not belong to its actual executing thread object.'}}
  $broadcasts=@($e.kernel_ipi.rendezvous.broadcasts)
  if($broadcasts.Count -ne 1 -or -not $broadcasts[0].completed -or @($broadcasts[0].members).Count -ne 12 -or $broadcasts[0].source_result -ne 0x1004){throw 'Real IPI TID proof missing.'}
  foreach($member in @($broadcasts[0].members)){$expected=if($member.processor -eq 0){0x1004}else{0x2000+$member.processor*4};if(-not $member.started -or $member.instruction_count -le 0 -or $member.result -ne $expected){throw 'IPI callback invented or aliased a guest thread ID.'}}
  $records+=@{original_controller_exit_known=(-not $reused);verified=$true;arch=$arch;partial=$partial;run=$run;reused=$reused;instructions=$e.instruction_count;request_sha256=$requestHash;result_sha256=$resultHash}
  @{schema=1;verified=$false;count=$records.Count;expected_count=4;records=$records}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8
 }
}
if($records.Count -ne 4){throw 'TID proof count mismatch.'}
@{schema=1;verified=$true;count=4;expected_count=4;records=$records;scope='Synthetic guest TIDs on actual existing root/created/borrowed thread lifetimes; no host ID or general sample admission.'}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8
$global:LASTEXITCODE=0
Write-Output 'Verified4 contained real root/CLIENT_ID/terminated-child/IPI guest-TID controls.'
