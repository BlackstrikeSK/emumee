param(
    [Parameter(Mandatory=$true)][string]$BundleDirectory,
    [Parameter(Mandatory=$true)][string]$FreshRoot,
    [Parameter(Mandatory=$true)][string]$PinnedReference
)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundle=[IO.Path]::GetFullPath($BundleDirectory)
$root=[IO.Path]::GetFullPath($FreshRoot)
$reference=[IO.Path]::GetFullPath($PinnedReference)
$cli=Join-Path $bundle 'emumee-rs.exe'
if(Test-Path -LiteralPath $root){throw 'Preserve existing control receipts; FreshRoot must not exist.'}
function Get-UnloadHash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
$receipt=Get-Content -LiteralPath (Join-Path $bundle 'rust-worker-build.json') -Raw|ConvertFrom-Json
$referenceHash=Get-UnloadHash $reference
if($referenceHash -cne '4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99'){throw 'Only the exact pinned kernel reference is allowed.'}
foreach($part in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
    if((Get-UnloadHash (Join-Path $bundle $part.file)) -cne $receipt.($part.key)){throw 'Frozen packaged binary differs from receipt.'}
}
$null=[IO.Directory]::CreateDirectory($root)
$generated=Join-Path $root 'generated'
$python=Join-Path $repo '.venv/Scripts/python.exe'
if(-not (Test-Path -LiteralPath $python -PathType Leaf)){$python='python'}
& $python (Join-Path $PSScriptRoot 'build_rust_unload_history_controls.py') $reference $generated
if($LASTEXITCODE -ne 0){throw 'Harmless unload controls could not be generated.'}
$expected=Get-Content -LiteralPath (Join-Path $generated 'generated-controls.json') -Raw|ConvertFrom-Json
$records=@()
foreach($case in $expected.cases){
    $source=Join-Path $generated $case.filename
    $run=Join-Path $root ('submitted-'+$case.name)
    if((Get-UnloadHash $source) -cne $case.sha256){throw 'Generated control changed before submission.'}
    & $cli submitted-driver $source $run --service UnloadControl --max-instructions 1000 --timeout-us 30000000 --kernel-code-reference $reference *> ($run+'.console.log')
    if($LASTEXITCODE -ne 0){throw "Generated control lacked verified processed worker evidence: $($case.name)"}
    $manifest=Get-Content -LiteralPath (Join-Path $run 'controller-manifest.json') -Raw|ConvertFrom-Json
    $request=Get-Content -LiteralPath (Join-Path $run 'request.json') -Raw|ConvertFrom-Json
    $ready=Get-Content -LiteralPath (Join-Path $run 'worker-ready.json') -Raw|ConvertFrom-Json
    $result=Get-Content -LiteralPath (Join-Path $run 'worker-result.json') -Raw|ConvertFrom-Json
    $engine=Get-Content -LiteralPath (Join-Path $run 'engine-report.json') -Raw|ConvertFrom-Json
    $witness=Get-Content -LiteralPath (Join-Path $run 'worker-containment.json') -Raw|ConvertFrom-Json
    $job=Get-Content -LiteralPath (Join-Path $run 'driver-job-profile.json') -Raw|ConvertFrom-Json
    $stop=Get-Content -LiteralPath (Join-Path $run 'worker-stop.json') -Raw|ConvertFrom-Json
    $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
    $requestHash=Get-UnloadHash (Join-Path $run 'request.json')
    if($manifest.status -cne 'verified' -or $manifest.guest_status -cne 'processed' -or $result.status -cne 'processed' -or $manifest.unpacking_confirmed -ne $false -or $result.unpacking_confirmed -ne $false){throw 'Control status is unverified or invents unpacking.'}
    foreach($row in @($manifest,$ready,$result.binding)){
        if($row.input_sha256 -cne $case.sha256 -or $row.request_sha256 -cne $requestHash -or $row.source_tree_sha256 -cne $receipt.source_tree_sha256 -or $row.kernel_code_reference_sha256 -cne $referenceHash -or $row.service_name -cne 'UnloadControl' -or $row.run_id -cne $request.run_id){throw 'Generated control source/request/input/reference binding differs.'}
    }
    foreach($key in @('controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Control used another frozen bundle.'}}
    if((Get-UnloadHash (Join-Path $run 'input.sys')) -cne $case.sha256 -or (Get-UnloadHash (Join-Path $run 'kernel-code-reference.pe')) -cne $referenceHash -or $request.kernel_code_reference_sha256 -cne $referenceHash -or $request.max_instructions -ne 1000 -or $request.timeout_us -ne 30000000 -or $manifest.worker_result_sha256 -cne (Get-UnloadHash (Join-Path $run 'worker-result.json')) -or $result.engine_report_sha256 -cne (Get-UnloadHash (Join-Path $run 'engine-report.json')) -or $engine.mode -cne 'submitted_driver_capture' -or $engine.binding.request_sha256 -cne $requestHash -or $engine.binding.source_tree_sha256 -cne $receipt.source_tree_sha256){throw 'Staged control, execution budget or typed report binding differs.'}
    if(-not $witness.app_container -or -not $witness.job_object -or -not $witness.child_process_blocked -or $witness.network_capabilities -ne 0 -or $job.profile -cne 'driver_capture_2048_v1' -or $job.process_memory_bytes -ne 2147483648 -or $job.active_process_limit -ne 1 -or $job.network_capabilities -ne 0 -or $job.peak_process_memory_bytes -le 0 -or $job.peak_process_memory_bytes -gt 2147483648 -or $manifest.cleanup -cne 'restored' -or $job.cleanup -cne 'restored' -or $stop.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $stop.worker.reason -cne 'exited' -or $stop.worker.exit_code -ne 0 -or $workerExit.exit_code -ne 0){throw 'Offline AppContainer/job/normal-exit/cleanup evidence differs.'}
    $execution=$engine.execution
    $policy=$execution.kernel_reference_unload_history
    if($execution.kernel_reference.mapping_mode -cne 'provider_same_base' -or [decimal]$execution.kernel_reference.target_base -ne [decimal]$expected.target_base -or $execution.kernel_reference.source_sha256 -cne $referenceHash -or $execution.kernel_reference.guest_unload_history_enabled -ne $true -or $execution.kernel_reference.reference_execution_admitted -ne $false -or $execution.kernel_reference.reference_instructions_executed -ne $false){throw 'Unload fields lack same-base inspection-only pinned reference authority.'}
    if($policy.profile -cne 'fresh-session-nt22631-unload-fields-v1' -or $policy.reference_sha256 -cne $referenceHash -or $policy.pdb_sha256 -cne $expected.pdb_sha256 -or $policy.generated_fixture -ne $false -or $policy.modeled_image_unloads -ne 0 -or $policy.native_read_guard_installed -ne $true -or @($policy.fields).Count -ne 2){throw 'Fresh unload-session field policy/provenance differs.'}
    foreach($field in $expected.fields){
        $actual=@($policy.fields|Where-Object {$_.name -ceq $field.name})
        if($actual.Count -ne 1 -or [decimal]$actual[0].address -ne [decimal]$field.address -or $actual[0].rva -ne $field.rva -or $actual[0].width -ne $field.width -or $actual[0].value -ne 0){throw 'Fresh-session NULL pointer/zero index identity, width or value differs.'}
    }
    if($policy.native_reads -ne 2 -or @($policy.observations).Count -ne 2 -or $policy.observations_omitted -ne 0 -or $policy.denials_omitted -ne 0){throw 'Control did not prove exactly both permitted native field loads.'}
    for($index=0;$index -lt 2;$index++){
        $observation=$policy.observations[$index];$field=$expected.fields[$index]
        if($observation.name -cne $field.name -or [decimal]$observation.address -ne [decimal]$field.address -or $observation.size -ne $field.width -or $observation.instruction_ordinal -le 0 -or $null -eq $observation.pc){throw 'Allowed native read lost exact field/address/width/execution evidence.'}
    }
    if($execution.api_calls -ne $case.api_calls -or @($execution.api_events).Count -ne $case.api_calls -or $execution.api_events_omitted -ne 0 -or $execution.network.calls -ne 0 -or $execution.api_events[0].api -cne 'ntoskrnl.KeGetCurrentIrql' -or $execution.api_events[0].result -ne 0 -or $null -ne $execution.api_events[0].error){throw 'Ordinary modeled kernel API execution differs.'}
    for($index=1;$index -lt $case.api_calls;$index++){if($execution.api_events[$index].api -cne 'ntoskrnl.RtlCopyMemory'){throw 'Control host read did not use the ordinary modeled copy API.'}}
    $denials=@($policy.denials)
    $fault=$execution.native_memory_fault
    if($case.name -eq 'read'){
        if($execution.completion_reason -cne 'entry_return' -or $execution.guest_entry_return -ne $expected.success -or $null -ne $execution.error -or $denials.Count -ne 0 -or $null -ne $fault -or @($execution.api_events|Where-Object {$null -ne $_.error}).Count -ne 0){throw 'Allowed native/host field reads failed, changed guest status, or invented denials.'}
    }else{
        if($execution.completion_reason -cne 'error' -or $null -ne $execution.guest_entry_return -or $execution.error -notmatch [regex]::Escape($case.error)){throw 'Out-of-field read/write/fetch falsely completed.'}
        $faultInstruction=[decimal]$execution.image_load.base+$case.fault_rva
        if(@($execution.instruction_tail|Where-Object {[decimal]$_.pc -eq $faultInstruction}).Count -ne 1){throw 'Negative case never reached its declared guest fault instruction.'}
        if($case.access -in @('native_read','api_read')){
            if($denials.Count -ne 1 -or $denials[0].access -cne $case.access -or [decimal]$denials[0].address -ne [decimal]$case.address -or $denials[0].size -ne $case.size -or $null -ne $fault){throw 'Readable-page field policy lost exact native/API read denial evidence.'}
            if($case.access -eq 'api_read' -and $execution.api_events[-1].error -notmatch [regex]::Escape($case.error)){throw 'Host-copy API failed for a reason other than field policy.'}
        }else{
            if($denials.Count -ne 0 -or $null -eq $fault -or $fault.access -cne $case.access -or [decimal]$fault.address -ne [decimal]$case.address -or $fault.size -ne $case.size -or [decimal]$fault.pc -notin @($faultInstruction,[decimal]$case.address)){throw 'Generic native WRITE/NX fault lost exact address/width/PC evidence.'}
        }
    }
    # Destination starts nonzero. Successful host copies must really clear it;
    # rejected copies must leave it untouched despite sharing a READ page.
    $snapshots=@($result.artifacts|Where-Object {@($_.observations|Where-Object {$_.kind -ceq 'memory_snapshot' -and $_.source -ceq 'settled_root_image'}).Count -gt 0})
    if($snapshots.Count -ne 1){throw 'Generated settled root snapshot missing.'}
    $snapshotPath=Join-Path (Join-Path $run 'artifacts') $snapshots[0].filename
    if((Get-UnloadHash $snapshotPath) -cne $snapshots[0].sha256){throw 'Generated settled snapshot hash differs.'}
    $snapshot=[IO.File]::ReadAllBytes($snapshotPath)
    $expectedByte=if($case.name -eq 'read'){0}else{0x55}
    for($index=0;$index -lt $expected.buffer_bytes;$index++){if($snapshot[$expected.buffer_rva+$index] -ne $expectedByte){throw 'Accepted/rejected host copy destination effects differ from policy.'}}
    & $cli inspect-driver-capture $run *> ($run+'.inspection.log')
    if($LASTEXITCODE -ne 0){throw 'Generated settled report/payload failed typed inspection.'}
    $records+=@{case=$case.name;verified=$true;source_tree_sha256=$receipt.source_tree_sha256;run=$run;input_sha256=$case.sha256;reference_sha256=$referenceHash;pdb_sha256=$policy.pdb_sha256;native_reads=$policy.native_reads;denials=$denials;native_fault=$fault;completion=$execution.completion_reason;error=$execution.error;instruction_count=$execution.instruction_count;cleanup='restored';unpacking_confirmed=$false}
    $records|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
}
if($records.Count -ne 7){throw 'Fresh unload-history control count differs.'}
Write-Output 'Verified 7 contained generated fresh unload-history controls: exact NULL/zero loads and host copies, same-page before/padding/cross-field/API refusals, WRITE/NX faults and restored cleanup.'
$global:LASTEXITCODE=0
