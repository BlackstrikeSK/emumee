param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing broker process evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='normal';qualified=$true;broker_exit=0;worker_exit=0;closed=$true;http=$true},
 @{name='miss';qualified=$true;broker_exit=0;worker_exit=0;closed=$true;denied=$true},
 @{name='dns';qualified=$true;broker_exit=0;worker_exit=0;closed=$true;denied=$true},
 @{name='crash';broker_exit=23;worker_exit=1;attempt=$true;reason='missing_close_marker'},
 @{name='partial';broker_exit=24;worker_exit=1;attempt=$true;reason='partial_record'},
 @{name='hang';broker_exit=1;worker_exit=2;attempt=$true;reason='missing_close_marker'},
 @{name='bad-id';broker_exit=2;worker_exit=1;reason='missing_close_marker'},
 @{name='bad-frame';broker_exit=2;worker_exit=1;reason='missing_close_marker'},
 @{name='worker-crash';broker_exit=1;worker_exit=25;reason='missing_close_marker'}
)
$records=@()
foreach($case in $cases) {
 $run=Join-Path $root $case.name
 & $exe broker-fixture $case.name $run *> ($run+'.console.log')
 $exit=$LASTEXITCODE
 $result=Get-Content -LiteralPath (Join-Path $run 'broker-session.json') -Raw | ConvertFrom-Json
 if($exit -ne [int](-not $case.qualified) -or $result.qualified -ne [bool]$case.qualified -or $result.broker_exit -ne $case.broker_exit -or $result.worker_exit -ne $case.worker_exit -or $result.cleanup -ne 'restored' -or $result.journal.closed -ne [bool]$case.closed -or $result.journal.stop_reason -ne $case.reason){throw "Broker process result changed: $($case.name). Read $run and its role-error files."}
 $ready=Get-Content -LiteralPath (Join-Path $run 'worker/client-ready.json') -Raw | ConvertFrom-Json
 if(-not $ready.private_journal_denied -or -not $ready.request_overwrite_denied -or -not $ready.response_append_denied -or -not $ready.ipc_creation_denied -or -not $ready.containment.app_container -or -not $ready.containment.job_object -or -not $ready.containment.child_process_blocked -or $ready.containment.network_capabilities -ne 0){throw 'Worker journal/IPC boundary failed.'}
 $server=Get-Content -LiteralPath (Join-Path $run 'broker/broker-ready.json') -Raw | ConvertFrom-Json
 if(-not $server.app_container -or -not $server.job_object -or -not $server.child_process_blocked -or $server.network_capabilities -ne 0){throw 'Broker containment failed.'}
 $journalPath=Join-Path $run 'private/network-broker.journal'
 if((Get-FileHash -LiteralPath $journalPath).Hash.ToLowerInvariant() -ne $result.journal.source_sha256){throw 'Recovered journal is not the original pinned private file.'}
 $success=@($result.journal.events | Where-Object {$_.event -eq 'http_request'})
 $attempts=@($result.journal.events | Where-Object {$_.event -eq 'http_request_attempt'})
 if($case.http) {
  if($success.Count -ne 1 -or $success[0].source -ne 'fixture' -or [Text.Encoding]::ASCII.GetString([byte[]]$result.worker_result.reply.value.body) -ne 'RUST BROKER'){throw 'Exact offline response changed.'}
 } elseif($success.Count -ne 0){throw 'Denied/interrupted request invented a successful HTTP result.'}
 if($case.attempt -and $attempts.Count -ne 1){throw 'Durable request attempt was lost after broker/worker failure.'}
 if($case.denied -and $result.worker_result.reply.ok){throw 'Offline miss/DNS was not denied.'}
 if((Test-Path -LiteralPath (Join-Path $run 'manifest.json')) -ne [bool]$case.qualified){throw 'Incomplete broker session was labeled qualified.'}
 $records+=@{case=$case.name;exit=$exit;qualified=$result.qualified;broker_exit=$result.broker_exit;worker_exit=$result.worker_exit;closed=$result.journal.closed;stop_reason=$result.journal.stop_reason;events=$result.journal.events.Count;valid_bytes=$result.journal.valid_bytes;unrecovered_bytes=$result.journal.unrecovered_bytes;source_sha256=$result.journal.source_sha256;verified=$true}
}
$records | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) two-process offline broker sessions, directional IPC, private journals and interrupted recovery."
