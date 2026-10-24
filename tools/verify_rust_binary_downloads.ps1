param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing native binary download evidence.'}
$null=New-Item -ItemType Directory -Path $root
$records=@()
foreach($arch in @('x86','x64')) {foreach($case in @('native-binary-a','native-binary-w','native-binary-partial','native-binary-empty','native-binary-miss')) {
 $run=Join-Path $root ($arch+'-'+$case)
 & $exe broker-fixture $case $run --arch $arch *> ($run+'.console.log')
 $exit=$LASTEXITCODE
 $partial=$case -eq 'native-binary-partial';$miss=$case -eq 'native-binary-miss';$empty=$case -eq 'native-binary-empty'
 $result=Get-Content -LiteralPath (Join-Path $run 'broker-session.json') -Raw | ConvertFrom-Json
 $e=$result.worker_result.execution
 if($exit -ne [int]$partial -or $result.qualified -ne (-not $partial) -or $result.worker_exit -ne 0 -or $result.broker_exit -ne 0 -or -not $result.journal.closed -or $result.cleanup -ne 'restored' -or $e.api_calls -ne 1 -or $e.network.calls -ne 1){throw "Binary guest execution failed: $arch $case"}
 if($partial) {
  if($e.completion_reason -ne 'instruction_budget' -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Partial binary transfer invented entry return.'}
 } else {
  $value=if($miss){2148270088}else{0}
  if($e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne $value -or $null -ne $e.error){throw 'Binary URLMon return changed.'}
 }
 $expectedBytes=if($miss -or $empty){0}else{65536}
 $expectedArtifacts=if($miss -or $empty){0}else{1}
 if($e.artifacts.Count -ne $expectedArtifacts -or $e.network.events[0].bytes -ne $expectedBytes){throw 'Binary file size/capture changed.'}
 if($e.network.events[0].destination_created -ne (-not $miss)){throw 'Empty/denied guest destination creation evidence changed.'}
 if($expectedArtifacts) {
  $a=$e.artifacts[0];$path=Join-Path (Join-Path $run 'worker/artifacts') $a.filename
  $bytes=[IO.File]::ReadAllBytes($path)
  if($bytes.Length -ne 65536 -or $a.size -ne 65536 -or $a.observations.Count -ne 2 -or $a.observations[0].source -ne 'urlmon_download' -or $a.observations[0].guest_path -ne 'c:\workspace\payload.bin'){throw 'Binary artifact metadata changed.'}
  for($i=0;$i -lt $bytes.Length;$i++){if($bytes[$i] -ne ($i % 256)){throw 'Binary guest payload changed.'}}
  if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -ne $a.sha256){throw 'Binary guest hash changed.'}
 }
 $success=@($result.journal.events | Where-Object {$_.event -eq 'http_request'})
 if($success.Count -ne [int](-not $miss) -or ($success.Count -and $success[0].size -ne $expectedBytes)){throw 'Guest binary transfer lacks broker evidence.'}
 $ready=Get-Content -LiteralPath (Join-Path $run 'worker/client-ready.json') -Raw | ConvertFrom-Json
 if(-not $ready.private_journal_denied -or -not $ready.private_fixtures_denied -or -not $ready.cleanup_plan_read_denied -or -not $ready.request_overwrite_denied -or -not $ready.response_append_denied -or -not $ready.ipc_creation_denied){throw 'Binary guest broker boundary regressed.'}
 $config=Get-Content -LiteralPath (Join-Path $run 'control/config.json') -Raw | ConvertFrom-Json
 if($config.schema -ne 4 -or $config.PSObject.Properties.Name -contains 'fixture_document' -or $config.fixture_document_sha256 -notmatch '^[0-9a-f]{64}$' -or (Get-FileHash -LiteralPath (Join-Path $run 'private/http-fixtures.json')).Hash.ToLowerInvariant() -ne $config.fixture_document_sha256){throw 'Fixture document was not pinned privately by hash.'}
 if((Test-Path -LiteralPath (Join-Path $run 'manifest.json')) -eq $partial){throw 'Binary partial run manifest qualification changed.'}
 $records+=@{arch=$arch;case=$case;qualified=$result.qualified;bytes=$expectedBytes;artifacts=$e.artifacts.Count;completion=$e.completion_reason;verified=$true}
}}
$records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained x86/x64 binary guest downloads and artifact/budget evidence."
