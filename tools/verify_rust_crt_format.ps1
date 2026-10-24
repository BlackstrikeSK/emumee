param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing CRT formatting evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='wide-console'},@{name='wide-stream'},@{name='wide-buffer'},@{name='equal'},@{name='truncate'},
 @{name='secure'},@{name='secure-truncate'},@{name='common-wide'},@{name='common-narrow'},@{name='integer64'},
 @{name='invalid-format';error='*conversion is not modeled*'},@{name='invalid-option';error='*locale or common formatting options*'},
 @{name='bad-format';error='*unreadable guest format/string*'},@{name='bad-output';error='*lacks permission*'},
 @{name='malformed-utf16';error='*malformed UTF16*'},@{name='surrogate-char';error='*isolated UTF16 surrogate*'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='crt-format-'+$case.name
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing CRT formatting instruction baseline.'};$budget=$baseline[0].instructions-1}else{$budget=3000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'CRT formatting containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 3 -or $e.api_events_omitted -ne 0 -or $e.artifacts.Count -ne 0 -or $e.network.calls -ne 0 -or $null -eq $e.console -or $null -eq $e.crt_stdio){throw "CRT formatting user/native/guest-only mismatch $arch ${kind}."}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "CRT formatting explicit stop mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "CRT formatting prefix fabricated return $arch ${kind}."}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "CRT formatting guest byte/count/poison assertions failed $arch ${kind}: $($e.error)"}
  if(@($e.api_events|Where-Object {$_.api -notlike 'msvcrt.*' -and $_.api -notlike 'ucrtbase.*' -and $_.api -notlike 'kernel32.*'}).Count){throw 'CRT formatting fixture module mismatch.'}
  if(-not $case.error){
   $events=@($e.api_events);if(@($events|Where-Object {$null -ne $_.error}).Count -or $events[-1].last_error -ne 0x12345678){throw 'CRT formatting changed LastError or reported API fault.'}
   $stdout='';$stderr='';$raw=[byte[]]@();$writes=0;$origin=''
   switch($case.name){
    'wide-console'{$stdout="$([char]0x3a9)$([char]::ConvertFromUtf32(0x1f600))|test|(null)|$([char]0x3a9)$([char]::ConvertFromUtf32(0x1f600))%";$raw=[Text.Encoding]::Unicode.GetBytes($stdout);$writes=1;$origin='formatted_wide'}
    'wide-stream'{$stderr="Host: $([char]0x3a9)$([char]::ConvertFromUtf32(0x1f600))`n";$raw=[Text.Encoding]::Unicode.GetBytes($stderr);$writes=1;$origin='formatted_wide'}
    'common-narrow'{$stderr="   test|test   `n";$raw=[Text.Encoding]::ASCII.GetBytes($stderr);$writes=1;$origin='formatted_narrow'}
    'integer64'{$stdout='1234567889abcdef:7';$raw=[Text.Encoding]::ASCII.GetBytes($stdout);$writes=1;$origin='formatted_narrow'}
   }
   if($e.console.stdout -cne $stdout -or $e.console.stderr -cne $stderr -or $e.console.raw_base64 -cne [Convert]::ToBase64String($raw) -or $e.console.raw_bytes -ne $raw.Length -or $e.console.write_events.Count -ne $writes -or $e.console.omitted_raw_bytes -ne 0 -or $e.console.omitted_events -ne 0 -or $e.console.stdout_truncated -or $e.console.stderr_truncated){throw "CRT formatting exact console/raw mismatch $arch ${kind}."}
   foreach($write in $e.console.write_events){$digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant();if($write.owner -ne 1024 -or $write.mode -ne 0x4000 -or $write.bytes -ne $raw.Length -or $write.retained_bytes -ne $raw.Length -or $write.raw_offset -ne 0 -or $write.sha256 -cne $digest -or $write.kind -ne $origin){throw 'CRT formatted write provenance mismatch.'}}
  }elseif($e.console.stdout -ne '' -or $e.console.stderr -ne '' -or $e.console.write_events.Count -ne 0){throw 'Rejected CRT format fabricated output.'}
  $records+=@{arch=$arch;case=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;verified=$true}
 }
}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 52){throw 'CRT formatting control count mismatch.'}
Write-Output "Verified $($records.Count) contained CRT formatting/varargs/buffer/count/console/refusal/budget controls."
$global:LASTEXITCODE=0
