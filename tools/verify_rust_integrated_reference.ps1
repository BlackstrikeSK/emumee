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
$receipt=Get-Content -LiteralPath (Join-Path $bundle 'rust-worker-build.json') -Raw|ConvertFrom-Json
if(Test-Path -LiteralPath $root){throw 'Preserve existing controls; FreshRoot must not exist.'}
if(-not (Test-Path -LiteralPath $cli -PathType Leaf)){throw 'Frozen packaged controller missing.'}
function Get-ControlHash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
$referenceHash=Get-ControlHash $reference
if($referenceHash -cne '4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99'){throw 'Only the exact pinned kernel reference is permitted.'}
foreach($part in @(@{file='emumee-rs.exe';key='controller_sha256'},@{file='emumee-worker.exe';key='worker_sha256'},@{file='unicorn.dll';key='unicorn_sha256'})){
    if((Get-ControlHash (Join-Path $bundle $part.file)) -cne $receipt.($part.key)){throw 'Frozen bundle binary differs from receipt.'}
}
$null=[IO.Directory]::CreateDirectory($root)
$generated=Join-Path $root 'generated'
$python=Join-Path $repo '.venv/Scripts/python.exe'
if(-not (Test-Path -LiteralPath $python -PathType Leaf)){$python='python'}
& $python (Join-Path $PSScriptRoot 'build_rust_integrated_reference_controls.py') $reference $generated
if($LASTEXITCODE -ne 0){throw 'Harmless generated reference controls could not be built.'}
$expected=Get-Content -LiteralPath (Join-Path $generated 'generated-controls.json') -Raw|ConvertFrom-Json
if($expected.reference_sha256 -cne $referenceHash -or @($expected.cases).Count -ne 4){throw 'Generated control manifest/reference differs.'}
$records=@()
foreach($case in $expected.cases){
    $controlInput=Join-Path $generated $case.filename
    $run=Join-Path $root ('submitted-'+$case.name)
    if((Get-ControlHash $controlInput) -cne $case.sha256){throw 'Generated input changed before submission.'}
    & $cli submitted-driver $controlInput $run --service RefControl --max-instructions 25000 --timeout-us 30000000 --kernel-code-reference $reference *> ($run+'.console.log')
    if($LASTEXITCODE -ne 0){throw "Packaged control did not produce verified processed evidence: $($case.name)"}
    # No offline broker/persona is requested: this uses the standard submitted
    # worker role and its root-level evidence documents.
    $manifest=Get-Content -LiteralPath (Join-Path $run 'controller-manifest.json') -Raw|ConvertFrom-Json
    $request=Get-Content -LiteralPath (Join-Path $run 'request.json') -Raw|ConvertFrom-Json
    $ready=Get-Content -LiteralPath (Join-Path $run 'worker-ready.json') -Raw|ConvertFrom-Json
    $result=Get-Content -LiteralPath (Join-Path $run 'worker-result.json') -Raw|ConvertFrom-Json
    $engine=Get-Content -LiteralPath (Join-Path $run 'engine-report.json') -Raw|ConvertFrom-Json
    $witness=Get-Content -LiteralPath (Join-Path $run 'worker-containment.json') -Raw|ConvertFrom-Json
    $job=Get-Content -LiteralPath (Join-Path $run 'driver-job-profile.json') -Raw|ConvertFrom-Json
    $stop=Get-Content -LiteralPath (Join-Path $run 'worker-stop.json') -Raw|ConvertFrom-Json
    $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
    $requestHash=Get-ControlHash (Join-Path $run 'request.json')
    if($manifest.status -cne 'verified' -or $manifest.guest_status -cne 'processed' -or $result.status -cne 'processed' -or $manifest.unpacking_confirmed -ne $false -or $result.unpacking_confirmed -ne $false){throw 'Control evidence is unverified or invents unpacking.'}
    foreach($row in @($manifest,$ready,$result.binding)){
        if($row.input_sha256 -cne $case.sha256 -or $row.request_sha256 -cne $requestHash -or $row.source_tree_sha256 -cne $receipt.source_tree_sha256 -or $row.kernel_code_reference_sha256 -cne $referenceHash -or $row.service_name -cne 'RefControl' -or $row.run_id -cne $request.run_id){throw 'Control request/input/reference/service/source receipt binding differs.'}
    }
    if((Get-ControlHash (Join-Path $run 'input.sys')) -cne $case.sha256 -or (Get-ControlHash (Join-Path $run 'kernel-code-reference.pe')) -cne $referenceHash -or $request.input_sha256 -cne $case.sha256 -or $request.input_size -ne (Get-Item -LiteralPath $controlInput).Length -or $request.kernel_code_reference_sha256 -cne $referenceHash -or $request.max_instructions -ne 25000 -or $request.timeout_us -ne 30000000){throw 'Staged generated input/reference or execution budget changed.'}
    foreach($key in @('controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Control used another frozen binary bundle.'}}
    if($manifest.worker_result_sha256 -cne (Get-ControlHash (Join-Path $run 'worker-result.json')) -or $result.engine_report_sha256 -cne (Get-ControlHash (Join-Path $run 'engine-report.json')) -or $engine.binding.request_sha256 -cne $requestHash -or $engine.binding.source_tree_sha256 -cne $receipt.source_tree_sha256 -or $engine.mode -cne 'submitted_driver_capture'){throw 'Typed engine/result report binding differs.'}
    if(-not $witness.app_container -or -not $witness.job_object -or -not $witness.child_process_blocked -or $witness.network_capabilities -ne 0 -or $job.profile -cne 'driver_capture_2048_v1' -or $job.process_memory_bytes -ne 2147483648 -or $job.active_process_limit -ne 1 -or $job.network_capabilities -ne 0 -or $job.peak_process_memory_bytes -le 0 -or $job.peak_process_memory_bytes -gt 2147483648 -or $manifest.cleanup -cne 'restored' -or $job.cleanup -cne 'restored' -or $stop.cleanup -cne 'restored' -or $workerExit.cleanup -cne 'restored' -or $stop.worker.reason -cne 'exited' -or $stop.worker.exit_code -ne 0 -or $workerExit.exit_code -ne 0){throw 'Generated control offline AppContainer/job/clean-exit evidence differs.'}
    $execution=$engine.execution
    $mapping=$execution.kernel_reference
    if($mapping.mapping_mode -cne 'provider_same_base' -or [decimal]$mapping.target_base -ne [decimal]$expected.target_base -or $mapping.source_sha256 -cne $referenceHash -or $mapping.section_count -ne @($expected.reference_sections).Count -or $mapping.redirected_code_exports -le 0 -or $mapping.redirected_code_exports -gt 3180 -or -not $mapping.read_only -or -not $mapping.non_executable -or $mapping.provider_dispatch_replaced -or $mapping.protected_data_replaced -or $mapping.reference_execution_admitted -or $mapping.reference_instructions_executed){throw 'Integrated reference address/redirection/READ-NX/admission receipt differs.'}
    $sections=@($mapping.reference_sections)
    if($sections.Count -ne @($expected.reference_sections).Count){throw 'Integrated reference section count differs.'}
    $fileBytes=0L;$mappedBytes=0L
    for($index=0;$index -lt $sections.Count;$index++){
        $actualSection=$sections[$index];$expectedSection=$expected.reference_sections[$index]
        foreach($key in @('name','rva','bytes','mapped_bytes')){if($actualSection.$key -cne $expectedSection.$key){throw 'Integrated reference section/RVA/file/mapped span differs from pinned input.'}}
        $fileBytes+=$expectedSection.bytes;$mappedBytes+=$expectedSection.mapped_bytes
    }
    if($mapping.file_backed_bytes -ne $fileBytes -or $mapping.mapped_bytes -ne $mappedBytes){throw 'Integrated reference byte accounting differs.'}
    $nt=@($execution.synthetic_providers|Where-Object {$_.module -ceq 'ntoskrnl.exe'})
    $hal=@($execution.loaded_modules|Where-Object {$_.name -ceq 'hal.dll'})
    if($nt.Count -ne 1 -or $hal.Count -ne 1 -or [decimal]$nt[0].base -ne [decimal]$expected.target_base -or [decimal]$hal[0].base -ne [decimal]([UInt64]::Parse('fffff8000f400000',[Globalization.NumberStyles]::HexNumber))){throw 'Integrated ntoskrnl/HAL module geometry differs.'}
    $catalog=$nt[0].reference_catalog
    if($catalog.protected_rva -ne $expected.reference_image_size -or $catalog.protected_size -ne $catalog.protected_symbols*4096 -or $nt[0].image_size -ne $catalog.protected_rva+$catalog.protected_size+4096 -or $nt[0].image_size -gt 33554432){throw 'Reference/private-protected/lock-page extent differs.'}
    if($execution.api_calls -ne 1 -or @($execution.api_events).Count -ne 1 -or $execution.api_events_omitted -ne 0 -or $execution.api_events[0].api -cne 'ntoskrnl.KeGetCurrentIrql' -or $execution.api_events[0].result -ne 0 -or $null -ne $execution.api_events[0].error -or $execution.network.calls -ne 0){throw 'Modeled API did not retain real execution while reference export stayed inspection-only.'}
    if($case.name -eq 'read'){
        if($execution.completion_reason -cne 'entry_return' -or $execution.guest_entry_return -ne $expected.success -or $null -ne $execution.error){throw 'Guest IAT target, reference byte, same-base relocation or modeled API checks failed.'}
    }else{
        if($execution.completion_reason -cne 'error' -or $null -ne $execution.guest_entry_return -or $execution.error -notmatch [regex]::Escape($case.error)){throw 'Reference guest write/fetch/private-gap protection was bypassed.'}
        $faultInstruction=[decimal]$execution.image_load.base+$case.fault_rva
        if(@($execution.instruction_tail|Where-Object {[decimal]$_.pc -eq $faultInstruction}).Count -ne 1){throw 'Negative control did not reach its declared generated guest fault instruction.'}
    }
    & $cli inspect-driver-capture $run *> ($run+'.inspection.log')
    if($LASTEXITCODE -ne 0){throw 'Generated control failed typed Driver128 report/payload inspection.'}
    $records+=@{case=$case.name;verified=$true;source_tree_sha256=$receipt.source_tree_sha256;run=$run;input_sha256=$case.sha256;reference_sha256=$referenceHash;mapping_mode=$mapping.mapping_mode;redirected_code_exports=$mapping.redirected_code_exports;completion=$execution.completion_reason;error=$execution.error;instruction_count=$execution.instruction_count;cleanup='restored';unpacking_confirmed=$false}
    $records|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
}
if($records.Count -ne 4){throw 'Integrated reference control count differs.'}
Write-Output 'Verified 4 contained generated submitted controls: actual reference EAT/IAT byte and relocation reads, modeled API execution, READ/NX write/fetch refusal, private-gap refusal and cleanup.'
$global:LASTEXITCODE=0
