param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$HeaderControls,[switch]$UploadControls,[switch]$ChunkControls)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing WinHTTP evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='winhttp';value=50462976;http=1;artifacts=1},
 @{name='winhttp-before-receive';value=50462976;http=1;artifacts=1;failed_api='*WinHttpReadData';win32=12019},
 @{name='winhttp-bad-read';value=50462976;http=1;artifacts=1;failed_api='*WinHttpReadData';win32=998},
 @{name='winhttp-bad-available';value=50462976;http=1;artifacts=1;failed_api='*WinHttpQueryDataAvailable';win32=998},
 @{name='winhttp-close-parent';value=0;http=1;artifacts=1;failed_api='*WinHttpReadData';win32=6},
 @{name='winhttp-miss';value=0;http=0;artifacts=0;failed_api='*WinHttpSendRequest';win32=12029},
 @{name='winhttp-async';http=0;artifacts=0;error='*asynchronous*'}
)
if($HeaderControls){$cases+=@(
 @{name='winhttp-query-status';value=50462976;http=1;artifacts=1;headers=$true},
 @{name='winhttp-query-small';value=50462976;http=1;artifacts=1;headers=$true;failed_api='*WinHttpQueryHeaders';win32=122},
 @{name='winhttp-query-custom';value=50462976;http=1;artifacts=1;headers=$true;failed_api='*WinHttpQueryHeaders';win32=12150},
 @{name='winhttp-query-raw';value=50462976;http=1;artifacts=1;headers=$true},
 @{name='winhttp-empty';value=0;http=1;artifacts=0;empty=$true}
)}
if($UploadControls){$cases+=@(
 @{name='winhttp-upload';value=50462976;http=1;artifacts=2;upload=$true},
 @{name='winhttp-upload-early';value=50462976;http=1;artifacts=2;upload=$true;failed_api='*WinHttpReceiveResponse';win32=12019},
 @{name='winhttp-upload-bad-count';value=50462976;http=1;artifacts=2;upload=$true;failed_api='*WinHttpWriteData';win32=998},
 @{name='winhttp-upload-overrun';value=50462976;http=1;artifacts=2;upload=$true;failed_api='*WinHttpWriteData';win32=87},
 @{name='winhttp-upload-incomplete';value=0;http=0;artifacts=0;upload=$true;failed_api='*WinHttpReceiveResponse';win32=12019},
 @{name='winhttp-upload-closed';value=0;http=0;artifacts=0;upload=$true;failed_api='*WinHttpWriteData';win32=6}
)}
if($ChunkControls){$cases+=@(
 @{name='winhttp-chunked';value=50462976;http=1;artifacts=2;upload=$true;chunked=$true},
 @{name='winhttp-chunked-split';value=50462976;http=1;artifacts=2;upload=$true;chunked=$true},
 @{name='winhttp-chunked-incomplete';value=0;http=0;artifacts=0;upload=$true;chunked=$true;failed_api='*WinHttpReceiveResponse';win32=12019},
 @{name='winhttp-chunked-malformed';http=0;artifacts=0;upload=$true;chunked=$true;error='*malformed chunk size*'},
 @{name='winhttp-chunked-zero';value=50462976;http=1;artifacts=2;upload=$true;chunked=$true;failed_api='*WinHttpWriteData';win32=87}
)}
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $run=Join-Path $root ($arch+'-'+$case.name)
 & $exe broker-fixture $case.name $run --arch $arch *> ($run+'.console.log')
 $exit=$LASTEXITCODE
 $result=Get-Content -LiteralPath (Join-Path $run 'broker-session.json') -Raw | ConvertFrom-Json
 $e=$result.worker_result.execution;$qualified=(-not [bool]$case.error)
 if($exit -ne [int](-not $qualified) -or $result.qualified -ne $qualified -or $result.worker_exit -ne 0 -or $result.broker_exit -ne 0 -or -not $result.journal.closed -or $result.cleanup -ne 'restored' -or $e.architecture -ne $arch -or $e.artifacts.Count -ne $case.artifacts){throw "WinHTTP execution mismatch: $arch $($case.name)"}
 if($case.error){if($e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw 'Unsupported asynchronous mode was guessed.'}}
 elseif($e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne $case.value -or $null -ne $e.error){throw 'WinHTTP guest did not read the expected actual response bytes.'}
 if($case.failed_api -and -not @($e.api_events | Where-Object {$_.api -like $case.failed_api -and $_.result -eq 0 -and $_.last_error -eq $case.win32}).Count){throw 'WinHTTP handle/state/output failure was not explicit.'}
 if($case.headers -and -not @($e.api_events | Where-Object {$_.api -like '*WinHttpQueryHeaders' -and $_.result -eq 1}).Count){throw 'WinHTTP header query did not return validated guest data.'}
 if($case.empty -and ($e.network.events[0].bytes -ne 0 -or $e.network.events[0].result -ne 1 -or -not @($e.api_events | Where-Object {$_.api -like '*WinHttpReadData' -and $_.result -eq 1}).Count)){throw 'WinHTTP empty EOF did not succeed with zero bytes.'}
 if(@($result.journal.events | Where-Object {$_.event -eq 'http_request'}).Count -ne $case.http){throw 'WinHTTP result lacks matching broker evidence.'}
 if($case.artifacts -and -not $case.upload){
  $a=$e.artifacts[0];$path=Join-Path (Join-Path $run 'worker/artifacts') $a.filename;$bytes=[IO.File]::ReadAllBytes($path)
  if($bytes.Length -ne 65536 -or $a.observations.Count -ne 1 -or $a.observations[0].source -ne 'winhttp_response' -or $a.observations[0].kind -ne 'memory_snapshot' -or $a.observations[0].guest_path -ne 'https://fixture.invalid:443/payload'){throw 'WinHTTP response capture/provenance changed.'}
  for($i=0;$i -lt $bytes.Length;$i++){if($bytes[$i] -ne ($i % 256)){throw 'WinHTTP binary response changed.'}}
  if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -ne $a.sha256){throw 'WinHTTP capture hash changed.'}
 }
 if($case.upload){
  $initialBytes=if($case.chunked){0}else{4}
  if($e.network.uploads.Count -lt 1 -or $e.network.uploads[0].phase -ne 'staged' -or $e.network.uploads[0].bytes -ne $initialBytes -or ($case.chunked -and $null -ne $e.network.uploads[0].total) -or (-not $case.chunked -and $e.network.uploads[0].total -ne 8)){throw 'Upload staging evidence changed.'}
  if($case.http){
   if($e.network.calls -ne 1 -or $e.network.events[0].api -ne 'WinHttpReceiveResponse' -or $e.network.uploads[-1].bytes -ne 8){throw 'Complete staged body was not published at receive.'}
   $request=@($e.artifacts | Where-Object {$_.observations[0].source -eq 'winhttp_request_body'})
   $response=@($e.artifacts | Where-Object {$_.observations[0].source -eq 'winhttp_response'})
   if($request.Count -ne 1 -or $response.Count -ne 1){throw 'Upload request/response provenance missing.'}
   $requestBytes=[IO.File]::ReadAllBytes((Join-Path (Join-Path $run 'worker/artifacts') $request[0].filename))
   if([Text.Encoding]::ASCII.GetString($requestBytes) -ne 'RUSTBODY'){throw 'Staged request body was truncated or a failed write appended bytes.'}
   $bodyHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($requestBytes)).ToLowerInvariant()
   $attempt=@($result.journal.events | Where-Object {$_.event -eq 'http_request_attempt'})
   if($attempt.Count -ne 1 -or $attempt[0].method -ne 'POST' -or $attempt[0].body_size -ne 8 -or $attempt[0].body_sha256 -ne $bodyHash -or $request[0].sha256 -ne $bodyHash){throw 'Durable broker attempt disagrees with staged request capture.'}
   if([bool]$attempt[0].chunked -ne [bool]$case.chunked){throw 'Decoded request chunked flag changed.'}
   $responseBytes=[IO.File]::ReadAllBytes((Join-Path (Join-Path $run 'worker/artifacts') $response[0].filename))
   if($responseBytes.Length -ne 65536){throw 'Upload response body size changed.'}
   for($i=0;$i -lt $responseBytes.Length;$i++){if($responseBytes[$i] -ne ($i % 256)){throw 'Upload response binary bytes changed.'}}
   if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($responseBytes)).ToLowerInvariant() -ne $response[0].sha256){throw 'Upload response hash changed.'}
  }elseif($e.network.calls -ne 0 -or @($result.journal.events | Where-Object {$_.event -eq 'http_request_attempt'}).Count -ne 0){throw 'Incomplete/closed upload reached the broker.'}
 }
 $ready=Get-Content -LiteralPath (Join-Path $run 'worker/client-ready.json') -Raw | ConvertFrom-Json
 if(-not $ready.private_journal_denied -or -not $ready.private_fixtures_denied -or -not $ready.cleanup_plan_read_denied -or -not $ready.request_overwrite_denied -or -not $ready.response_append_denied -or -not $ready.ipc_creation_denied){throw 'WinHTTP weakened the contained broker boundary.'}
 if((Test-Path -LiteralPath (Join-Path $run 'manifest.json')) -ne $qualified){throw 'WinHTTP manifest qualification changed.'}
 $records+=@{arch=$arch;case=$case.name;qualified=$qualified;completion=$e.completion_reason;return=$e.guest_entry_return;api_calls=$e.api_calls;instructions=$e.instruction_count;artifacts=$e.artifacts.Count;verified=$true}
}}
$records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained x86/x64 WinHTTP handle/readiness/buffer/read/denial controls."
