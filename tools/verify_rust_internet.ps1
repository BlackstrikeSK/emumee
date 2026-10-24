param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$HeaderControls,[switch]$PostControls,[switch]$StreamControls)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing WinINet evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='internet-ansi'},@{name='internet-wide'},@{name='internet-split'},
 @{name='internet-empty';empty=$true},@{name='internet-miss';miss=$true;failed_api='*InternetOpenUrl*';win32=12029},
 @{name='internet-closed';failed_api='*InternetReadFile';win32=6},
 @{name='internet-bad-read';failed_api='*InternetReadFile';win32=998},
 @{name='internet-bad-count';failed_api='*InternetReadFile';win32=87},
 @{name='internet-null-available'},
 @{name='internet-flags';error='*flags/context/cache/callback*'},
 @{name='internet-async';error='*asynchronous*'}
)
$records=@()
if($HeaderControls){$cases+=@(
 @{name='internet-query-a';headers=$true},@{name='internet-query-w';headers=$true},
 @{name='internet-query-small-a';headers=$true;failed_api='*HttpQueryInfo*';win32=122},
 @{name='internet-query-small-w';headers=$true;failed_api='*HttpQueryInfo*';win32=122},
 @{name='internet-query-custom-a';headers=$true;failed_api='*HttpQueryInfo*';win32=12150},
 @{name='internet-query-custom-w';headers=$true;failed_api='*HttpQueryInfo*';win32=12150},
 @{name='internet-query-null';headers=$true;failed_api='*HttpQueryInfo*';win32=122},
 @{name='internet-query-read-only';headers=$true;failed_api='*HttpQueryInfo*';win32=998},
 @{name='internet-query-missing';headers=$true;failed_api='*HttpQueryInfo*';win32=12150}
)}
if($PostControls){$cases+=@(
 @{name='internet-post-a';post=$true},@{name='internet-post-w';post=$true},
 @{name='internet-send-wide-length';post=$true;failed_api='*HttpSendRequest*';win32=87},
 @{name='internet-send-before-read';post=$true;failed_api='*HttpSendRequest*';win32=12019}
)}
if($StreamControls){$cases+=@(
 @{name='internet-stream-a';post=$true;stream=$true},@{name='internet-stream-w';post=$true;stream=$true},
 @{name='internet-stream-zero';post=$true;stream=$true;failed_api='*InternetWriteFile';win32=87},
 @{name='internet-stream-linked';post=$true;stream=$true;linked=$true},
 @{name='internet-stream-full';post=$true;stream=$true;full=$true},
 @{name='internet-stream-empty';post=$true;stream=$true;empty_post=$true},
 @{name='internet-stream-bad-count';post=$true;stream=$true;failed_api='*InternetWriteFile';win32=87},
 @{name='internet-stream-excess';post=$true;stream=$true;failed_api='*InternetWriteFile';win32=87},
 @{name='internet-stream-bad-struct';post=$true;stream=$true;no_request=$true;bad_struct=$true;failed_api='*HttpSendRequestEx*';win32=87},
 @{name='internet-stream-incomplete';post=$true;stream=$true;no_request=$true;error='*incomplete end*'},
 @{name='internet-stream-closed';post=$true;stream=$true;no_request=$true;failed_api='*InternetWriteFile';win32=6}
)}
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $run=Join-Path $root ($arch+'-'+$case.name)
 & $exe broker-fixture $case.name $run --arch $arch *> ($run+'.console.log')
 $exit=$LASTEXITCODE
 $result=Get-Content -LiteralPath (Join-Path $run 'broker-session.json') -Raw | ConvertFrom-Json
 $e=$result.worker_result.execution;$qualified=-not [bool]$case.error
 if($exit -ne [int](-not $qualified) -or $result.qualified -ne $qualified -or $result.worker_exit -ne 0 -or $result.broker_exit -ne 0 -or -not $result.journal.closed -or $result.cleanup -ne 'restored' -or $e.architecture -ne $arch){throw "WinINet containment/result mismatch $arch $($case.name)"}
 if($case.error){if($e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw 'Unmodeled WinINet behavior fabricated success.'}}
 elseif($e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne [int](-not [bool]$case.miss) -or $null -ne $e.error){throw "WinINet guest stream/EOF checks failed $arch $($case.name): $($e.error)"}
 if($case.failed_api -and -not @($e.api_events | Where-Object {$_.api -like $case.failed_api -and $_.result -eq 0 -and $_.last_error -eq $case.win32}).Count){throw 'WinINet failure did not report exact guest error.'}
 $expectedCalls=[int](-not [bool]($case.error -or $case.no_request))
 $expectedCaptures=[int](-not [bool]($case.error -or $case.empty -or $case.miss))
 if($case.post){$expectedCaptures+=1}
 if($case.empty_post){$expectedCaptures=1}
 if($case.error -or $case.no_request){$expectedCaptures=0}
 if($e.network.calls -ne $expectedCalls -or $e.artifacts.Count -ne $expectedCaptures -or @($result.journal.events | Where-Object {$_.event -eq 'http_request_attempt'}).Count -ne $expectedCalls){throw 'WinINet capture/request timing is inconsistent.'}
 if($expectedCaptures){
  $response=@($e.artifacts|Where-Object {$_.observations[0].source -eq 'wininet_response'})
  if($response.Count -ne 1){throw 'WinINet response capture missing/duplicated.'}
  $a=$response[0];$path=Join-Path (Join-Path $run 'worker/artifacts') $a.filename;$bytes=[IO.File]::ReadAllBytes($path)
  $url=if($case.post){'https://fixture.invalid:443/payload'}else{'https://fixture.invalid/payload'}
  if($bytes.Length -ne 65536 -or $a.observations.Count -ne 1 -or $a.observations[0].source -ne 'wininet_response' -or $a.observations[0].kind -ne 'memory_snapshot' -or $a.observations[0].guest_path -ne $url){throw 'WinINet response capture/provenance changed.'}
  for($i=0;$i -lt $bytes.Length;$i++){if($bytes[$i] -ne ($i % 256)){throw 'WinINet binary response changed.'}}
  if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -ne $a.sha256){throw 'WinINet capture hash changed.'}
 }
 if($case.headers -and -not @($e.api_events|Where-Object {$_.api -like '*HttpQueryInfo*' -and $_.result -eq 1}).Count){throw 'WinINet query did not return actual header data.'}
 if($case.post -and -not $case.no_request -and -not $case.error){
  $request=@($e.artifacts|Where-Object {$_.observations[0].source -eq 'wininet_request_body'})
  $postApi=if($case.stream){'HttpEndRequest'}else{'HttpSendRequest'}
  if($e.network.events[0].api -ne $postApi){throw 'WinINet POST capture/effect missing.'}
  if($case.empty_post){
   if($request.Count -ne 0){throw 'Empty request body fabricated an artifact.'}
   $hash='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  }else{
   if($request.Count -ne 1){throw 'WinINet POST body capture missing/duplicated.'}
   $requestBytes=[IO.File]::ReadAllBytes((Join-Path (Join-Path $run 'worker/artifacts') $request[0].filename))
   if([Text.Encoding]::ASCII.GetString($requestBytes) -ne 'RUSTBODY'){throw 'WinINet POST body changed.'}
   $hash=(Get-FileHash -LiteralPath (Join-Path (Join-Path $run 'worker/artifacts') $request[0].filename)).Hash.ToLowerInvariant()
   if($request[0].sha256 -ne $hash){throw 'WinINet request capture hash changed.'}
  }
  $attempt=@($result.journal.events|Where-Object {$_.event -eq 'http_request_attempt'})
  $bodySize=if($case.empty_post){0}else{8};$headerCount=if($case.empty_post){0}else{1}
  if($attempt.Count -ne 1 -or $attempt[0].method -ne 'POST' -or $attempt[0].body_size -ne $bodySize -or $attempt[0].header_count -ne $headerCount -or $attempt[0].chunked -or $attempt[0].body_sha256 -ne $hash){throw 'WinINet durable request disagrees with guest POST body.'}
 }
 if($case.stream){
  if($case.bad_struct){if($e.network.uploads.Count -ne 0){throw 'Invalid INTERNET_BUFFERS changed pending state.'}}
  else{
   $initial=if($case.empty_post){0}elseif($case.full){8}else{4};$total=if($case.empty_post){0}else{8}
   $phase=if($case.linked){'staged_head_only'}else{'staged'}
   if($e.network.uploads.Count -lt 1 -or $e.network.uploads[0].bytes -ne $initial -or $e.network.uploads[0].total -ne $total -or $e.network.uploads[0].phase -ne $phase){throw 'Stream head/length staging evidence mismatch.'}
   if(-not $case.no_request -and $e.network.uploads[-1].bytes -ne $total){throw 'Completed stream body was not complete before EndRequest.'}
  }
 }
 if($case.empty -and ($e.network.events[0].bytes -ne 0 -or $e.network.events[0].result -ne 1)){throw 'Empty WinINet response was fabricated.'}
 $ready=Get-Content -LiteralPath (Join-Path $run 'worker/client-ready.json') -Raw | ConvertFrom-Json
 if(-not $ready.private_journal_denied -or -not $ready.private_fixtures_denied -or -not $ready.cleanup_plan_read_denied -or -not $ready.request_overwrite_denied -or -not $ready.response_append_denied -or -not $ready.ipc_creation_denied){throw 'WinINet weakened the contained broker boundary.'}
 if((Test-Path -LiteralPath (Join-Path $run 'manifest.json')) -ne $qualified){throw 'WinINet manifest qualification changed.'}
 $records+=@{arch=$arch;case=$case.name;qualified=$qualified;completion=$e.completion_reason;return=$e.guest_entry_return;api_calls=$e.api_calls;instructions=$e.instruction_count;artifacts=$e.artifacts.Count;verified=$true}
}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained x86/x64 WinINet binary stream/EOF/denial controls."
$global:LASTEXITCODE=0
