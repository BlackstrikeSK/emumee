param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing controller recovery evidence.'}
$null=New-Item -ItemType Directory -Path $root
# Run exclusively: no other test may consume this bundle's abandoned plan.
$original=(Get-Acl -LiteralPath $bundlePath).Sddl
$records=@()
foreach($case in @('controller-crash','controller-partial')) {
 $run=Join-Path $root $case
 & $exe broker-fixture $case $run *> ($run+'.console.log')
 if($LASTEXITCODE -ne 27){throw "Controlled parent did not reach hard exit: $case"}
 $ready=Get-Content -LiteralPath (Join-Path $run 'controller-ready.json') -Raw | ConvertFrom-Json
 $client=Get-Content -LiteralPath (Join-Path $run 'worker/client-ready.json') -Raw | ConvertFrom-Json
 $server=Get-Content -LiteralPath (Join-Path $run 'broker/broker-ready.json') -Raw | ConvertFrom-Json
 if(-not $client.cleanup_plan_read_denied -or -not $server.cleanup_plan_read_denied -or -not $client.private_journal_denied){throw 'A contained role could read private controller/broker state.'}
 $journal=Join-Path $run 'private/network-broker.journal'
 $hash=(Get-FileHash -LiteralPath $journal).Hash
 if($case -eq 'controller-crash') {
  $next=Join-Path $root ('next-'+$case)
  & $exe fixture --arch x64 --iterations 10 --isolated-output $next *> ($next+'.console.log')
  if($LASTEXITCODE -ne 0){throw 'Ordinary launch did not automatically recover its predecessor.'}
  $manifest=Get-Content -LiteralPath (Join-Path $next 'manifest.json') -Raw | ConvertFrom-Json
  if($manifest.result.execution.guest_entry_return -ne 10){throw 'Analysis after recovery did not execute its own fixture.'}
  $recovery=$manifest.controller_recovery
 } else {
  & $exe recover-bundle > (Join-Path $root ($case+'-recovery.json')) 2> (Join-Path $root ($case+'-recovery.stderr.txt'))
  if($LASTEXITCODE -ne 0){throw 'Torn cleanup intent was not recovered.'}
  $recovery=Get-Content -LiteralPath (Join-Path $root ($case+'-recovery.json')) -Raw | ConvertFrom-Json
 }
 if(-not $recovery.recovered -or $recovery.profiles -ne 2 -or $recovery.jobs -ne 2 -or $recovery.grants -ne 12 -or $recovery.partial_tail -ne ($case -eq 'controller-partial')){throw 'Cleanup plan recovery counts/partial intent changed.'}
 if((Get-Acl -LiteralPath $bundlePath).Sddl -ne $original){throw 'Recovery failed to restore the exact original bundle DACL.'}
 if((Get-FileHash -LiteralPath $journal).Hash -ne $hash){throw 'Controller cleanup altered broker evidence.'}
 if(Test-Path -LiteralPath (Join-Path $run 'manifest.json')){throw 'Crashed analysis was labeled successful by recovery.'}
 $pids=@($ready.broker_pid,$ready.worker_pid)
 $remaining=@(Get-CimInstance Win32_Process | Where-Object {$_.ProcessId -in $pids -and $_.ExecutablePath -eq (Join-Path $bundlePath 'emumee-worker.exe')})
 if($remaining.Count){throw 'Owned broker/worker survived controller recovery.'}
 & $exe recover-bundle > (Join-Path $root ($case+'-repeat.json'))
 if($LASTEXITCODE -ne 0){throw 'Recovery was not idempotent.'}
 $repeat=Get-Content -LiteralPath (Join-Path $root ($case+'-repeat.json')) -Raw | ConvertFrom-Json
 if($repeat.recovered -or $repeat.profiles -ne 0 -or $repeat.grants -ne 0 -or $repeat.jobs -ne 0){throw 'Completed cleanup plan was replayed again.'}
 $records+=@{case=$case;recovery=$recovery;worker_cleanup_plan_read_denied=$client.cleanup_plan_read_denied;broker_cleanup_plan_read_denied=$server.cleanup_plan_read_denied;original_bundle_dacl_restored=$true;broker_journal_unchanged=$true;old_run_unqualified=$true;owned_processes_remaining=$remaining.Count;verified=$true}
}
$records | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output 'Verified automatic/explicit controller hard-exit recovery, torn plans, private vault, exact DACL restoration and idempotence.'
$global:LASTEXITCODE=0
