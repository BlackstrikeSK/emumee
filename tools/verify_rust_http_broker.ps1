param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$RequirePrivateFixtures)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing HTTP broker evidence.'}
$null=New-Item -ItemType Directory -Path $root
$records=@()
foreach($case in @('http-binary','http-post','http-headers','http-body-miss','http-chunked-miss')) {
 $run=Join-Path $root $case
 & $exe broker-fixture $case $run *> ($run+'.console.log')
 if($LASTEXITCODE -ne 0){throw "HTTP broker fixture failed: $case"}
 $result=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json
 if(-not $result.qualified -or -not $result.journal.closed -or $result.cleanup -ne 'restored'){throw 'HTTP fixture did not finish with qualified containment/cleanup.'}
 $ready=Get-Content -LiteralPath (Join-Path $run 'worker/client-ready.json') -Raw | ConvertFrom-Json
 $server=Get-Content -LiteralPath (Join-Path $run 'broker/broker-ready.json') -Raw | ConvertFrom-Json
 if(-not $ready.cleanup_plan_read_denied -or -not $server.cleanup_plan_read_denied -or -not $ready.private_journal_denied -or -not $ready.request_overwrite_denied -or -not $ready.response_append_denied -or -not $ready.ipc_creation_denied){throw 'HTTP transport weakened the private/directional boundary.'}
 if($RequirePrivateFixtures -and -not $ready.private_fixtures_denied){throw 'Worker could read private HTTP fixture document.'}
 $attempts=@($result.journal.events | Where-Object {$_.event -eq 'http_request_attempt'})
 $matches=@($result.journal.events | Where-Object {$_.event -eq 'network_fixture_match'})
 $success=@($result.journal.events | Where-Object {$_.event -eq 'http_request'})
 if($attempts.Count -ne 1){throw 'HTTP attempt evidence missing.'}
 $reply=$result.worker_result.reply
 if($case -like '*-miss') {
  if($reply.ok -or $success.Count -ne 0 -or $matches.Count -ne 0){throw 'Nonmatching body/chunked flag received a fixture response.'}
 } else {
  $response=$reply.value.response
  if(-not $reply.ok -or $reply.value.kind -ne 'http_full' -or $response.status -ne 206 -or $response.reason -ne 'Fixture partial' -or $response.version -ne 'HTTP/1.0' -or $response.headers.Count -ne 2 -or $response.headers[0][1] -ne 'one' -or $response.headers[1][1] -ne 'two' -or $matches.Count -ne 1 -or $success.Count -ne 1){throw 'HTTP response metadata/order changed.'}
  $bytes=[Convert]::FromBase64String($response.body)
  if($bytes.Length -ne 65536){throw 'Binary body was truncated.'}
  for($i=0;$i -lt $bytes.Length;$i++){if($bytes[$i] -ne ($i % 256)){throw 'Binary body content changed.'}}
  $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
  if($success[0].sha256 -ne $hash -or $success[0].size -ne $bytes.Length){throw 'Private journal body evidence changed.'}
 }
 $journal=Join-Path $run 'private/network-broker.journal'
 if((Get-FileHash -LiteralPath $journal).Hash.ToLowerInvariant() -ne $result.journal.source_sha256){throw 'Recovered journal identity changed.'}
 $records+=@{case=$case;binary_bytes=$(if($reply.ok){65536}else{0});denied=(-not $reply.ok);private_plan_denied=$true;directional_ipc=$true;verified=$true}
}
$records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained binary/exact-request HTTP broker controls."
