param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$CaptureControls)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing registry evidence.'}
$null=New-Item -ItemType Directory -Path $root
$records=@()
$kinds=@('lifecycle','enumeration','small-buffer','default-value','invalid-handle','closed-handle','read-only','options')
foreach($arch in @('x86','x64')){foreach($encoding in @('a','w')){foreach($kind in $kinds){
 $name='registry-'+$kind+'-'+$encoding
 $negative=$kind -eq 'options'
 $modes=@('full')
 if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){
   $baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $name -and -not $_.partial})
   if($baseline.Count -ne 1){throw 'Missing registry instruction baseline.'}
   $budget=$baseline[0].instructions-1
  }else{$budget=1000}
  $run=Join-Path $root ($arch+'-'+$name+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $name --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Registry containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.kernel_cpu -or $e.api_calls -lt 2 -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0){throw 'Registry native/user/guest-only report mismatch.'}
  if($CaptureControls){
   $expected=if($kind -in @('lifecycle','enumeration','small-buffer')){1}else{0}
   if($e.artifacts.Count -ne $expected -or $e.capture_summary.omitted_observations -ne 0 -or $e.capture_summary.omitted_bytes -ne 0){throw 'Registry capture count/omission mismatch.'}
   $accepted=@($e.api_events|Where-Object {$_.api -like 'advapi32.RegSetValueEx*' -and $_.result -eq 0 -and $_.arguments[3] -eq 3 -and $_.arguments[5] -gt 0})
   if($accepted.Count -ne $expected){throw 'Registry capture did not match an accepted binary write.'}
   if($expected){
    $a=$e.artifacts[0]
    $payload=[IO.File]::ReadAllBytes((Join-Path $run ('artifacts/'+$a.filename)))
    $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($payload)).ToLowerInvariant()
    if([Convert]::ToHexString($payload) -ne 'F00080FF' -or $a.size -ne 4 -or $a.sha256 -ne $sha -or $a.filename -ne ($sha+'.bin') -or $a.observations.Count -ne 1){throw 'Registry capture payload bytes/hash/size/filename mismatch.'}
    $o=$a.observations[0]
    if($o.kind -ne 'registry_value' -or $o.source -ne 'registry_value' -or $o.guest_path -cne 'HKEY_CURRENT_USER\Software\EmumeeRegistryFixture\Raw' -or $o.context.registry_key -cne 'HKEY_CURRENT_USER\Software\EmumeeRegistryFixture' -or $o.context.registry_value -cne 'Raw' -or $o.context.registry_type -ne 3){throw 'Registry capture typed provenance mismatch.'}
   }
  }elseif($e.artifacts.Count -ne 0){throw 'Legacy registry fixture unexpectedly captured artifacts; use CaptureControls for the new profile.'}
  if($negative){
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notlike '*Registry creation options*'){throw "Registry options profile fabricated a return $arch ${name}: $($e.error)"}
  }elseif($partial){
   if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "Registry budget stop fabricated a return $arch ${name}."}
  }elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 17 -or $null -ne $e.error){throw "Registry guest status/bytes/length/handle checks failed $arch ${name}: $($e.error)"}
  if(@($e.api_events|Where-Object {$_.last_error -ne 0x12345678 -or ($_.api -notlike 'advapi32.Reg*' -and $_.api -notin @('kernel32.SetLastError','kernel32.GetLastError'))}).Count){throw "Registry module or LastError preservation changed $arch ${name}."}
  $records+=@{arch=$arch;case=$name;encoding=$encoding;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;capture_controls=[bool]$CaptureControls;artifacts=$e.artifacts.Count;verified=$true}
 }
}}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
if($records.Count -ne 60){throw 'Registry control count mismatch.'}
Write-Output "Verified $($records.Count) contained registry byte/count/status/access/enumeration/handle/budget controls."
$global:LASTEXITCODE=0
