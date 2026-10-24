param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing MDL evidence; use a fresh output root.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='mdl-lifecycle';calls=6;descriptors=0;aliases=0;backing=0;pool=0;frames=3},
 @{name='mdl-alias';calls=10;descriptors=0;aliases=0;backing=0;pool=0;frames=3},
 @{name='mdl-read-only-cpu';error='WRITE_PROT';calls=6;descriptors=1;aliases=1;backing=3;pool=2;frames=3;readonly=$true},
 @{name='mdl-read-only-api';error='read-only MDL alias|lacks permission';calls=7;descriptors=1;aliases=1;backing=3;pool=2;frames=3;readonly=$true},
 @{name='mdl-nx';error='FETCH_PROT';calls=6;descriptors=1;aliases=1;backing=3;pool=2;frames=3},
 @{name='mdl-unmapped';error='READ_UNMAPPED';calls=10;descriptors=0;aliases=0;backing=0;pool=0;frames=3},
 @{name='mdl-free-active';error='MDL with active mappings';calls=7;descriptors=1;aliases=1;backing=3;pool=2;frames=3},
 @{name='mdl-pool-free-active';error='active MDL aliases';calls=7;descriptors=1;aliases=1;backing=3;pool=2;frames=3},
 @{name='mdl-flags';error='unsupported mapping priority';calls=5;descriptors=1;aliases=0;backing=0;pool=2;frames=3},
 @{name='mdl-geometry';error='modified descriptor geometry';calls=3;descriptors=1;aliases=0;backing=0;pool=2;frames=0;unbuilt=$true},
 @{name='mdl-unbuilt';error='not been built/locked';calls=3;descriptors=1;aliases=0;backing=0;pool=2;frames=0;unbuilt=$true}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $modes=@('full');if(-not $case.error){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){
   $baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.case -eq $case.name -and -not $_.partial})
   if($baseline.Count -ne 1){throw 'Missing MDL instruction baseline.'}
   $budget=$baseline[0].instructions-1
  }else{$budget=1000}
  $run=Join-Path $root ($arch+'-'+$case.name+$(if($partial){'-partial'}else{''}))
  & $exe fixture --kind $case.name --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
  $exit=$LASTEXITCODE
  $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw|ConvertFrom-Json
  $e=$result.execution;$mdl=$e.kernel_mdls;$model=$mdl.model
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'MDL packaged worker containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $null -eq $e.kernel_entry -or $null -eq $mdl -or $e.api_calls -ne $case.calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0){throw "MDL native/kernel/offline report mismatch $arch $($case.name)."}
  if($case.error){
   if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch $case.error){throw "MDL negative mismatch $arch $($case.name): $($e.error)"}
  }elseif($partial){
   if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw "MDL budget stop fabricated entry return $arch $($case.name)."}
  }elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "MDL guest geometry/PFN/coherence/lifetime checks failed $arch $($case.name): $($e.error)"}
  if(@($model.descriptors.PSObject.Properties).Count -ne $case.descriptors -or @($model.aliases.PSObject.Properties).Count -ne $case.aliases -or @($model.frames.PSObject.Properties).Count -ne $case.frames -or $mdl.owned_backing_pages -ne $case.backing -or @($e.kernel_pool.allocations.PSObject.Properties).Count -ne $case.pool -or $mdl.native_effect_failure -or $mdl.capture_skipped_ranges -ne 0){throw "MDL lifecycle/backing/PFN state mismatch $arch $($case.name)."}
  if(@($e.api_events|Where-Object {$_.api -notlike 'ntoskrnl.*' -or $_.last_error -ne 0}).Count){throw 'MDL calls escaped the kernel guest-only profile or changed Win32 last error.'}
  foreach($property in @($model.aliases.PSObject.Properties)){
   $a=$property.Value
   if($a.size -ne 12288 -or $a.owner -ne 4 -or [bool]$a.readonly -ne [bool]$case.readonly){throw 'MDL alias extent/owner/protection mismatch.'}
  }
  $expectedArtifacts=if($case.descriptors){2}else{0}
  if(@($e.artifacts).Count -ne $expectedArtifacts){throw 'MDL live evidence count mismatch.'}
  foreach($artifact in @($e.artifacts)){
   if($artifact.filename -notmatch '^[0-9a-f]{64}\.bin$' -or $artifact.observations.Count -ne 1 -or $artifact.observations[0].kind -ne 'memory_snapshot' -or $artifact.observations[0].source -notin @('kernel_mdl_descriptor','kernel_mdl_buffer')){throw 'MDL snapshot provenance/type changed.'}
   $path=Join-Path (Join-Path $run 'artifacts') $artifact.filename
   $bytes=[IO.File]::ReadAllBytes($path)
   if($bytes.Length -ne $artifact.size -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $artifact.sha256){throw 'MDL snapshot bytes/hash mismatch.'}
   if($artifact.observations[0].source -eq 'kernel_mdl_buffer'){
    if($bytes.Length -ne 8192 -or [Text.Encoding]::ASCII.GetString($bytes,0,4) -ne 'EMU!'){throw 'Rejected MDL operation changed its source buffer.'}
   }else{
    $width=if($arch -eq 'x64'){8}else{4};$header=if($arch -eq 'x64'){48}else{28};$start=if($arch -eq 'x64'){32}else{16}
    $expectedSize=$header+3*$width
    if($bytes.Length -ne $expectedSize -or [BitConverter]::ToUInt16($bytes,$width) -ne $expectedSize -or [BitConverter]::ToUInt16($bytes,$width+2) -ne $(if($case.unbuilt){0}else{4}) -or [BitConverter]::ToUInt32($bytes,$start+$width+4) -ne 0x123){throw 'Captured MDL header/offset mismatch.'}
    $expectedLength=if($case.name -eq 'mdl-geometry'){4096}else{8192}
    if([BitConverter]::ToUInt32($bytes,$start+$width) -ne $expectedLength){throw 'Captured MDL byte count mismatch.'}
    for($index=0;$index -lt 3;$index++){
     $pfn=if($width -eq 8){[BitConverter]::ToUInt64($bytes,$header+$index*$width)}else{[BitConverter]::ToUInt32($bytes,$header+$index*$width)}
     if($pfn -ne $(if($case.unbuilt){0}else{256+$index})){throw 'Captured MDL PFN array mismatch.'}
    }
   }
  }
  $records+=@{arch=$arch;case=$case.name;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;descriptors=$case.descriptors;aliases=$case.aliases;verified=$true}
 }
}}
if($records.Count -ne 26){throw 'MDL control count mismatch.'}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained MDL ABI/layout/PFN/coherence/permissions/lifecycle/budget controls."
$global:LASTEXITCODE=0
