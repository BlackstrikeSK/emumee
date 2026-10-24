param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[Parameter(Mandatory=$true)][string]$RecoveryRoot)
$ErrorActionPreference='Stop'
# Run exclusively after this bundle's existing two controller recovery controls.
# Only fixed generated CFB data goes into the static worker, never real samples.
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
$recoveryPath=[IO.Path]::GetFullPath((Join-Path $repo $RecoveryRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing static MSI worker evidence.'}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$recovery=@(Get-Content -LiteralPath (Join-Path $recoveryPath 'verification.json') -Raw|ConvertFrom-Json)
if($recovery.Count -ne 2 -or @($recovery|Where-Object {-not $_.verified -or -not $_.broker_journal_unchanged -or -not $_.original_bundle_dacl_restored -or -not $_.old_run_unqualified -or $_.owned_processes_remaining -ne 0}).Count){throw 'MSI worker qualification requires the completed two controller-journal/DACL/private-state recovery gates.'}
$recoveryManifest=Get-Content -LiteralPath (Join-Path $recoveryPath 'next-controller-crash/manifest.json') -Raw|ConvertFrom-Json
if($recoveryManifest.source_tree_sha256 -ne $receipt.source_tree_sha256 -or $recoveryManifest.controller_sha256 -ne $receipt.controller_sha256 -or $recoveryManifest.worker_sha256 -ne $receipt.worker_sha256){throw 'Recovery gates belong to another frozen build.'}
$null=New-Item -ItemType Directory -Path $root
@{verified=$false;stage='running'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'qualification.json') -Encoding utf8NoBOM
@{source_tree_sha256=$receipt.source_tree_sha256;recovery_root=$recoveryPath;controller_recovery_gates=2;scope='Generated static CFB worker only; no sample execution.'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'qualification-input.json') -Encoding utf8NoBOM
$bundleDacl=(Get-Acl -LiteralPath $bundlePath).Sddl
function Get-Hash([byte[]]$Data){return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Data)).ToLowerInvariant()}
function Put-U16([byte[]]$Data,[int]$At,[uint16]$Value){[BitConverter]::GetBytes($Value).CopyTo($Data,$At)}
function Put-U32([byte[]]$Data,[int]$At,[uint32]$Value){[BitConverter]::GetBytes($Value).CopyTo($Data,$At)}
function Get-OwnedPe {
 $pe=New-Object byte[] 1024
 $pe[0]=0x4d;$pe[1]=0x5a;Put-U32 $pe 0x3c 0x80;$pe[0x80]=0x50;$pe[0x81]=0x45
 foreach($row in @(@(0x84,0x8664),@(0x86,1),@(0x94,0xf0),@(0x98,0x20b))){Put-U16 $pe $row[0] $row[1]}
 foreach($row in @(@((0x98+56),0x2000),@((0x98+60),0x200),@((0x188+12),0x1000),@((0x188+16),0x200),@((0x188+20),0x200))){Put-U32 $pe $row[0] $row[1]}
 for($i=512;$i -lt 1024;$i++){$pe[$i]=0x52}
 return ,$pe
}
$ownedPe=Get-OwnedPe
$mapped=New-Object byte[] 8192
[Array]::Copy($ownedPe,0,$mapped,0,512);[Array]::Copy($ownedPe,512,$mapped,4096,512)
if((Get-Hash $ownedPe) -ne 'ba92945c53cd44d480152f8a4ce40ffa7e70f74dbe892d2df7f4dbe182324a62' -or (Get-Hash $mapped) -ne '500d8c482908e0015e15b440eabd518c7b90eed929e7de4fe9ef5ffbd1d7229e'){throw 'Owned PE fixture expectation changed.'}
$cases=@('mini-v3','mini-v4','regular-v3','regular-v4','difat-v3','data-pe','mapped-data-pe','corrupt-fat','truncated','tamper-request','tamper-input','unknown-request-field','foreign-owned-fixture')
$records=@()
foreach($case in $cases){
 $exit=$null;$stop=$null;$result=$null
 try {
 $run=Join-Path $root $case
 & $exe msi-fixture $case $run *> ($run+'.console.log')
 $exit=$LASTEXITCODE
 if($exit -ne 0){throw "Static MSI fixture controller failed ${case}: exit$exit"}
 $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
 $stop=Get-Content -LiteralPath (Join-Path $run 'worker-stop.json') -Raw|ConvertFrom-Json
 $witness=Get-Content -LiteralPath (Join-Path $run 'worker-containment.json') -Raw|ConvertFrom-Json
 if(-not $manifest.qualified -or $manifest.fixture -ne 'generated_static_msi' -or $manifest.cleanup -ne 'restored' -or $manifest.source_tree_sha256 -ne $receipt.source_tree_sha256 -or $stop.cleanup -ne 'restored' -or $stop.worker.reason -ne 'exited'){throw 'MSI fixture receipt/lifecycle binding failed.'}
 if(-not $witness.app_container -or -not $witness.job_object -or -not $witness.child_process_blocked -or $witness.network_capabilities -ne 0){throw 'MSI static worker containment failed.'}
 if((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $run 'input.msi')).Hash.ToLowerInvariant() -ne $manifest.input_sha256 -or (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $run 'request.json')).Hash.ToLowerInvariant() -ne $manifest.staged_request_sha256){throw 'Worker changed its staged input/request.'}
 $tamper=$case -in @('tamper-request','tamper-input','unknown-request-field','foreign-owned-fixture')
 $rejected=$case -in @('corrupt-fat','truncated')
 $result=$manifest.result
 $expected=@()
 if($tamper){
  if($stop.worker.exit_code -ne 2 -or $result.status -ne 'rejected_before_inspection' -or (Test-Path -LiteralPath (Join-Path $run 'msi-result.json')) -or (Test-Path -LiteralPath (Join-Path $run 'artifacts'))){throw 'MSI tamper control fabricated inspection/artifacts.'}
 }else{
  $resultPath=Join-Path $run 'msi-result.json'
  if($stop.worker.exit_code -ne 0 -or (Get-FileHash -Algorithm SHA256 -LiteralPath $resultPath).Hash.ToLowerInvariant() -ne $manifest.result_sha256 -or $result.role -ne 'generated_static_msi' -or $result.completion_reason -ne 'static_inspection' -or $result.instruction_count -ne 0 -or $result.network_calls -ne 0 -or $result.request_sha256 -ne $manifest.request_sha256 -or $result.input_sha256 -ne $manifest.input_sha256){throw 'MSI static report binding/execution scope failed.'}
  if($rejected){if($result.status -ne 'rejected' -or $null -ne $result.inspection -or -not $result.inspection_error -or $result.artifacts.Count){throw 'Malformed CFB recovered fabricated evidence.'}}
  else{
   if($result.status -ne 'inspected' -or $result.inspection.inspection -ne 'static_streams' -or $null -ne $result.inspection_error -or $result.capture_summary.omitted_observations -ne 0){throw 'Generated valid CFB static inspection failed.'}
   if($case -like 'mini-*'){$expected+=@{data=[byte[]](0x4d,0x53,0x43,0x46,0,0xff);kind='container_stream';path=@('Binary','Cabinet')}}
   elseif($case -like 'regular-*'){$cab=New-Object byte[] 4096;$cab[0]=0x4d;$cab[1]=0x53;$cab[2]=0x43;$cab[3]=0x46;$expected+=@{data=$cab;kind='container_stream';path=@('Cabinet')}}
   elseif($case -eq 'data-pe'){$expected+=@{data=$ownedPe;kind='carved_image';path=@('Payload')}}
   elseif($case -eq 'mapped-data-pe'){$expected+=@{data=$mapped;kind='memory_snapshot';path=@('Payload')};$expected+=@{data=$ownedPe;kind='carved_image';path=@('Payload')}}
  }
  if($result.artifacts.Count -ne $expected.Count){throw 'Static MSI artifact count differs from concrete expected captures.'}
  foreach($item in $expected){
   $sha=Get-Hash $item.data
   $found=@($result.artifacts|Where-Object {$_.sha256 -ceq $sha})
   if($found.Count -ne 1){throw 'MSI expected payload hash absent/duplicated.'}
   $a=$found[0];$payload=[IO.File]::ReadAllBytes((Join-Path $run ('artifacts/'+$a.filename)))
   if($a.filename -cne ($sha+'.bin') -or $a.size -ne $item.data.Length -or (Get-Hash $payload) -cne $sha -or [Convert]::ToHexString($payload) -cne [Convert]::ToHexString($item.data) -or $a.observations.Count -ne 1){throw 'MSI captured bytes/size/hash/provenance count changed.'}
   $o=$a.observations[0]
   if($o.kind -cne $item.kind -or $o.guest_path -ne '' -or (($o.context.container_stream_path -join '|') -cne ($item.path -join '|'))){throw 'MSI typed provenance/path changed.'}
   if($item.kind -in @('carved_image','memory_snapshot')){
    if($o.context.capture_origin -ne 'container_stream' -or $o.context.carve_source -ne 'msi_stream:Payload@0x6'){throw 'MSI carving origin/source changed.'}
    if($item.kind -eq 'carved_image' -and $o.context.carved_kind -ne 'structural_pe'){throw 'MSI carved PE was mislabeled.'}
    if($case -eq 'mapped-data-pe' -and ($o.context.layout -ne 'mapped_image' -or $o.context.reconstruction -ne 'section_rva_to_raw' -or $o.context.image_size -ne 8192)){throw 'MSI mapped reconstruction lost evidence metadata.'}
   }
  }
 }
 if((Get-Acl -LiteralPath $bundlePath).Sddl -cne $bundleDacl){throw 'MSI fixture failed to restore the exact bundle DACL.'}
 $records+=@{case=$case;exit=$exit;worker_exit=$stop.worker.exit_code;status=$result.status;instruction_count=$result.instruction_count;expected_artifacts=$expected.Count;contained=$true;exact_bundle_dacl_restored=$true;verified=$true}
 $records|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }catch{
  $records+=@{case=$case;exit=$exit;worker_exit=$stop.worker.exit_code;verified=$false;error=$_.Exception.Message}
  $records|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
  @{verified=$false;stage='failed';case=$case;error=$_.Exception.Message}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'qualification.json') -Encoding utf8NoBOM
  throw
 }
}
& $exe recover-bundle > (Join-Path $root 'repeat-recovery.json') 2> (Join-Path $root 'repeat-recovery.stderr.txt')
if($LASTEXITCODE -ne 0){throw 'MSI cleanup plan idempotence check failed.'}
$repeat=Get-Content -LiteralPath (Join-Path $root 'repeat-recovery.json') -Raw|ConvertFrom-Json
if($repeat.recovered -or $repeat.profiles -ne 0 -or $repeat.jobs -ne 0 -or $repeat.grants -ne 0){throw 'MSI controller left an unfinished recovery plan.'}
& (Join-Path $repo 'tools/check_residual_appcontainer.ps1') -Roots @($bundlePath,$root) -WorkerRoots @($bundlePath) *> (Join-Path $root 'residual-check.log')
if($LASTEXITCODE -ne 0){throw 'MSI static worker left owned profile/grant/process residue.'}
if($records.Count -ne 13){throw 'MSI static worker control count mismatch.'}
@{verified=$true;controls=$records.Count;controller_recovery_gates=2;exact_bundle_dacl_restored=$true;cleanup_plan_idempotent=$true;residual_check_passed=$true}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'qualification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained generated static-MSI stream/artifact/reconstruction/tamper controls with bound prior recovery gates, exact DACL restoration and zero residual resources."
$global:LASTEXITCODE=0
