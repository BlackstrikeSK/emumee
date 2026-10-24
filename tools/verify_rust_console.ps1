param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing guest console evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(@{name='standard'},@{name='ansi'},@{name='wide'},@{name='file'},@{name='mixed'},@{name='redirect'},@{name='alias'},@{name='closed'},@{name='read-only'},@{name='mode'},@{name='screen'},@{name='bad-buffer'},@{name='bad-count'},@{name='reserved'},@{name='zero'},@{name='invalid-handle'},@{name='input';error='*stdin input is not modeled*'},@{name='overlapped';error='*Console overlapped I/O is not modeled*'})
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='console-'+$case.name
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing guest console instruction baseline.'};$budget=$baseline[0].instructions-1}else{$budget=4000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Guest console containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 2 -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or $null -eq $e.console -or $null -eq $e.console_session -or $null -eq $e.crt_stdio -or $e.console_session.code_page -ne 437){throw "Guest console user/native/profile report mismatch $arch ${kind}."}
  if($case.error){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "Guest console explicit stop mismatch $arch ${kind}: $($e.error)"}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "Guest console prefix fabricated return $arch ${kind}."}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Guest console byte/count/pointer/error/poison checks failed $arch ${kind}: $($e.error)"}
  if(@($e.api_events|Where-Object {$_.api -notlike 'kernel32.*' -and $_.api -notlike 'msvcrt.*'}).Count){throw 'Guest console fixture module mismatch.'}
  if(-not $case.error){
   $events=@($e.api_events);if(@($events|Where-Object {$null -ne $_.error}).Count -or $events[-1].last_error -ne 0x12345678){throw 'Guest console positive contains API fault or wrong final LastError.'}
   $stdout='';$stderr='';$segments=@();$unicode="$([char]0x3a9)$([char]::ConvertFromUtf32(0x1f600))"
   switch($case.name){
    'ansi'{$stdout=[string][char]0xe9;$segments+=@{kind='write_console_a';raw=[byte[]]@(0x82);fd=1;mode=3;encoding='cp437'}}
    'wide'{$stderr=$unicode+[char]0xfffd;$segments+=@{kind='write_console_w';raw=[byte[]]@(0xa9,3,0x3d,0xd8,0,0xde);fd=2;mode=3;encoding='utf16_le_lossy'};$segments+=@{kind='write_console_w';raw=[byte[]]@(0,0xd8);fd=2;mode=3;encoding='utf16_le_lossy'}}
    'file'{$stdout=[string][char]0xe9;$segments+=@{kind='write_file';raw=[byte[]]@(0x82);fd=1;mode=3;encoding='cp437'}}
    'alias'{$stdout=([string][char]0xe9)*2;$segments+=@{kind='write_console_a';raw=[byte[]]@(0x82);fd=1;mode=3;encoding='cp437'};$segments+=@{kind='write_file';raw=[byte[]]@(0x82);fd=1;mode=3;encoding='cp437'}}
    'mixed'{$stdout='a'+([string][char]0xe9)*2+$unicode+'z';$segments+=@{kind='descriptor';raw=[byte[]]@(0x61);fd=1;mode=0x4000;encoding='ascii'};$segments+=@{kind='write_file';raw=[byte[]]@(0x82);fd=1;mode=3;encoding='cp437'};$segments+=@{kind='write_console_a';raw=[byte[]]@(0x82);fd=1;mode=3;encoding='cp437'};$segments+=@{kind='write_console_w';raw=[byte[]]@(0xa9,3,0x3d,0xd8,0,0xde);fd=1;mode=3;encoding='utf16_le_lossy'};$segments+=@{kind='formatted_wide';raw=[byte[]]@(0x7a,0);fd=1;mode=0x4000;encoding='utf16_le'}}
   }
   $raw=[byte[]]@($segments|ForEach-Object {$_.raw})
   if($e.console.stdout -cne $stdout -or $e.console.stderr -cne $stderr -or $e.console.raw_base64 -cne [Convert]::ToBase64String($raw) -or $e.console.raw_bytes -ne $raw.Length -or $e.console.write_events.Count -ne $segments.Count -or $e.console.omitted_raw_bytes -ne 0 -or $e.console.omitted_events -ne 0 -or $e.console.stdout_truncated -or $e.console.stderr_truncated){throw "Guest console exact text/raw/order mismatch $arch ${kind}."}
   $offset=0
   for($index=0;$index -lt $segments.Count;$index++){$expected=$segments[$index];$write=$e.console.write_events[$index];$digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expected.raw)).ToLowerInvariant();if($write.kind -ne $expected.kind -or $write.encoding -ne $expected.encoding -or $write.descriptor -ne $expected.fd -or $write.mode -ne $expected.mode -or $write.owner -ne 1024 -or $write.bytes -ne $expected.raw.Length -or $write.retained_bytes -ne $expected.raw.Length -or $write.raw_offset -ne $offset -or $write.sha256 -cne $digest){throw 'Guest console shared raw provenance mismatch.'};$offset+=$expected.raw.Length}
   if($case.name -eq 'mode'){if($e.console_session.input_mode -ne 6 -or $e.console_session.output_mode -ne 7){throw 'Guest console shared mode state mismatch.'}}elseif($e.console_session.input_mode -ne 0xf7 -or $e.console_session.output_mode -ne 3){throw 'Guest console mode changed unexpectedly.'}
   if($case.name -eq 'alias'){if($e.console_session.aliases.Count -ne 0 -or (@($e.console_session.retired_aliases)-join ',') -ne '61696,61697'){throw 'Guest console aliases did not retire both A/W handles.'}}
  }elseif($e.console.stdout -ne '' -or $e.console.stderr -ne '' -or $e.console.write_events.Count -ne 0){throw 'Unimplemented console input/overlapped fabricated output.'}
  if($case.name -eq 'redirect'){
   if($e.artifacts.Count -ne 1){throw 'Redirected guest VFS write artifact missing.'};$a=$e.artifacts[0];$file=Join-Path (Join-Path $run 'artifacts') $a.filename;$payload=[IO.File]::ReadAllBytes($file)
   if([Text.Encoding]::ASCII.GetString($payload) -cne 'file' -or $a.size -ne 4 -or (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant() -cne $a.sha256 -or $a.observations.Count -ne 1 -or $a.observations[0].kind -ne 'guest_file' -or $a.observations[0].guest_path -ne 'c:\workspace\console-redirect.bin'){throw 'Redirected console handle lost ordinary guest-file bytes/provenance.'}
  }elseif($e.artifacts.Count -ne 0){throw 'Console APIs fabricated file artifacts.'}
  $records+=@{arch=$arch;case=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;verified=$true}
 }
}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 68){throw 'Guest console control count mismatch.'}
Write-Output "Verified $($records.Count) contained console/stdhandle/codepage/mode/alias/redirect/shared-output/error/budget controls."
$global:LASTEXITCODE=0
