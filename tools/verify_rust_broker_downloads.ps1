param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Use a fresh broker guest download root.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='native-a';qualified=$true;value=0;artifacts=1;http=1;attempts=1;network=1},
 @{name='native-w';qualified=$true;value=0;artifacts=1;http=1;attempts=1;network=1},
 @{name='native-miss';qualified=$true;value=2148270088;artifacts=0;http=0;attempts=1;network=1;network_error='*No exact*'},
 @{name='native-parent';qualified=$true;value=0;artifacts=0;http=1;attempts=1;network=1;network_error='*cancelled*'},
 @{name='native-callback';artifacts=0;http=0;attempts=0;network=0;error='*callback*'},
 @{name='native-null';artifacts=0;http=0;attempts=0;network=0;error='*null*'},
 @{name='native-partial';artifacts=1;http=1;attempts=1;network=1;partial=$true}
)
$records=@()
foreach($arch in @('x86','x64')) {foreach($case in $cases) {
 $run=Join-Path $root ($arch+'-'+$case.name)
 & $exe broker-fixture $case.name $run --arch $arch *> ($run+'.console.log')
 $exit=$LASTEXITCODE
 $result=Get-Content -LiteralPath (Join-Path $run 'broker-session.json') -Raw | ConvertFrom-Json
 $e=$result.worker_result.execution
 if($exit -ne [int](-not $case.qualified) -or $result.qualified -ne [bool]$case.qualified -or $result.worker_exit -ne 0 -or $result.broker_exit -ne 0 -or -not $result.journal.closed -or $result.cleanup -ne 'restored' -or $e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $e.api_calls -ne 1 -or $e.network.calls -ne $case.network -or $e.artifacts.Count -ne $case.artifacts){throw "Broker guest execution mismatch: $arch $($case.name)"}
 $completeCount=if($arch -eq 'x64'){11}else{8}
 if($case.partial) {
  $expectedCount=if($arch -eq 'x64'){10}else{7}
  if($e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $expectedCount -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Partial native download invented completion.'}
 } elseif($case.error) {
  if($e.completion_reason -ne 'error' -or $e.error -notlike $case.error -or $null -ne $e.guest_entry_return){throw 'Unsupported URLMon input was not explicit.'}
 } elseif($e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne $case.value -or $e.instruction_count -ne $completeCount -or $null -ne $e.error){throw 'URLMon ABI return/count changed.'}
 if($case.network_error -and $e.network.events[0].error -notlike $case.network_error){throw 'Native network denial/cancellation evidence was lost.'}
 if(@($result.journal.events | Where-Object {$_.event -eq 'http_request'}).Count -ne $case.http -or @($result.journal.events | Where-Object {$_.event -eq 'http_request_attempt'}).Count -ne $case.attempts){throw 'Guest transfer does not match the private broker journal.'}
 if($case.artifacts) {
  $a=$e.artifacts[0];$path=Join-Path (Join-Path $run 'worker/artifacts') $a.filename
  if([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($path)) -ne 'RUST BROKER' -or (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -ne $a.sha256 -or $a.observations.Count -ne 2 -or $a.observations[0].source -ne 'urlmon_download' -or $a.observations[0].guest_path -ne 'c:\workspace\payload.bin'){throw 'Native broker payload/provenance changed.'}
 }
 $ready=Get-Content -LiteralPath (Join-Path $run 'worker/client-ready.json') -Raw | ConvertFrom-Json
 if(-not $ready.private_journal_denied -or -not $ready.request_overwrite_denied -or -not $ready.response_append_denied -or -not $ready.ipc_creation_denied -or $ready.containment.network_capabilities -ne 0){throw 'Guest broker isolation regressed.'}
 if((Test-Path -LiteralPath (Join-Path $run 'manifest.json')) -ne [bool]$case.qualified){throw 'Partial/error guest download received a qualified manifest.'}
 $records+=@{arch=$arch;case=$case.name;qualified=$result.qualified;completion=$e.completion_reason;instructions=$e.instruction_count;return=$e.guest_entry_return;error=$e.error;artifacts=$e.artifacts.Count;http=$case.http;verified=$true}
}}
$records | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) isolated x86/x64 guest URLMon-to-broker transfer/artifact controls."
