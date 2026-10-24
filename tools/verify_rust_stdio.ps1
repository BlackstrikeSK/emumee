param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing stdio evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='legacy'},@{name='ucrt'},@{name='errno'},@{name='modes'},@{name='write'},@{name='utf16'},@{name='utf8'},
 @{name='bad-encoding';error='*ASCII*'},@{name='bad-buffer';error='*not readable guest memory*'},
 @{name='bad-descriptor';error='*descriptor or byte count*'},@{name='owned-free';error='*CRT-owned FILE/errno*'},
 @{name='owned-protect';error='*CRT-owned FILE/errno*'},@{name='owned-recommit';error='*CRT-owned FILE/errno*'},
 @{name='format-unsupported';error='*real guest format model*'}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='stdio-'+$case.name
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){
   $baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $kind -and -not $_.partial})
   if($baseline.Count -ne 1){throw 'Missing stdio instruction baseline.'};$budget=$baseline[0].instructions-1
  }else{$budget=2000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Stdio containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 2 -or $e.api_events_omitted -ne 0 -or $e.artifacts.Count -ne 0 -or $e.network.calls -ne 0 -or $null -eq $e.console -or $null -eq $e.crt_stdio){throw "Stdio user/native/guest-only report mismatch $arch ${kind}."}
  if($case.error){
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike $case.error){throw "Stdio explicit stop mismatch $arch ${kind}: $($e.error)"}
  }elseif($partial){
   if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "Stdio prefix fabricated return $arch ${kind}."}
  }elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Stdio guest assertions failed $arch ${kind}: $($e.error)"}
  if(@($e.api_events|Where-Object {$_.api -notlike 'msvcrt.*' -and $_.api -notlike 'kernel32.*'}).Count){throw 'Stdio fixture module mismatch.'}
  if(-not $case.error){
   $events=@($e.api_events);if(@($events|Where-Object {$null -ne $_.error}).Count -or $events[-1].last_error -ne 0x12345678){throw 'Stdio changed LastError or reported API fault.'}
   $stdout='';$stderr='';$raw=[byte[]]@();$writes=0
   switch($case.name){
    'write'{$stdout="hello`n";$stderr=$stdout;$raw=[Text.Encoding]::ASCII.GetBytes($stdout+$stderr);$writes=2}
    'utf16'{$stdout="A$([char]0x3a9)`n";$raw=[Text.Encoding]::Unicode.GetBytes($stdout);$writes=1}
    'utf8'{$stdout="A$([char]0xe9)`n";$raw=[Text.Encoding]::UTF8.GetBytes($stdout);$writes=1}
   }
   if($e.console.stdout -cne $stdout -or $e.console.stderr -cne $stderr -or $e.console.raw_base64 -cne [Convert]::ToBase64String($raw) -or $e.console.raw_bytes -ne $raw.Length -or $e.console.write_events.Count -ne $writes -or $e.console.omitted_raw_bytes -ne 0 -or $e.console.omitted_events -ne 0 -or $e.console.stdout_truncated -or $e.console.stderr_truncated){throw "Stdio decoded/raw capture mismatch $arch ${kind}."}
   foreach($write in $e.console.write_events){
    $segment=[byte[]]@($raw[$write.raw_offset..($write.raw_offset+$write.retained_bytes-1)])
    $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($segment)).ToLowerInvariant()
    if($write.owner -ne 1024 -or $write.bytes -ne $write.retained_bytes -or $write.sha256 -cne $digest){throw 'Stdio raw write provenance mismatch.'}
   }
  }elseif($e.console.stdout -ne '' -or $e.console.stderr -ne '' -or $e.console.write_events.Count -ne 0){throw 'Rejected stdio call fabricated console output.'}
  if($case.name -like 'owned-*' -and -not @($e.api_events|Where-Object {$_.api -eq 'msvcrt._errno' -and $_.result -gt 0}).Count){throw 'Stdio owned guard did not obtain guest storage.'}
  $records+=@{arch=$arch;case=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;verified=$true}
 }
}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 42){throw 'Stdio control count mismatch.'}
Write-Output "Verified $($records.Count) contained CRT stdio/layout/errno/raw console/ownership/budget controls."
$global:LASTEXITCODE=0
