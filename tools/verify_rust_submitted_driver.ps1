param(
    [Parameter(Mandatory=$true)][string]$BundleDirectory,
    [Parameter(Mandatory=$true)][string]$FreshRoot
)
$ErrorActionPreference = 'Stop'
$cli = Join-Path $BundleDirectory 'emumee-rs.exe'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'Packaged controller missing' }
if (Test-Path -LiteralPath $FreshRoot) { throw 'Verification root must be fresh' }
$root = [System.IO.Path]::GetFullPath($FreshRoot)
[System.IO.Directory]::CreateDirectory($root) | Out-Null
$fixture = Join-Path $root 'generated-driver'
$submitted = Join-Path $root 'submitted-TestDrv'
$source = Join-Path $root 'TestDrv.sys'

# This creates input.bin using only the repository-owned harmless DriverEntry64
# recipe. It is the already-qualified closed fixture role, not a submitted file.
& $cli driver-capture-fixture driver-entry64 $fixture | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Closed generated driver fixture failed' }
$fixtureManifest = Get-Content -LiteralPath (Join-Path $fixture 'manifest.json') -Raw | ConvertFrom-Json
if ($fixtureManifest.status -ne 'completed') { throw 'Closed fixture did not complete' }
$closedInput = Join-Path $fixture 'input.bin'
$closedRecipeHash = (Get-FileHash -LiteralPath $closedInput -Algorithm SHA256).Hash.ToLowerInvariant()
if ($closedRecipeHash -cne 'a3bcdd9a2ec6d4bf818b3b341dc2eb88f1cea4981fb111e35896e513a46c55fa') {
    throw 'Closed generated DriverEntry64 source recipe differs'
}
Copy-Item -LiteralPath $closedInput -Destination $source
# The closed recipe declares a 64 MiB image but has only a tiny .data section.
# Extend that generated section's virtual span to the image end, preserving its
# raw bytes and DriverEntry, so the settled *guest* mapping is fully readable.
$generatedImageBytes = [uint32](64 * 1024 * 1024)
$dataVirtualSizeOffset = 0x98 + 0xf0 + 40 + 8
$sourceHandle = [System.IO.File]::Open($source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try {
    $sourceHandle.Position = $dataVirtualSizeOffset
    $virtualBytes = [System.BitConverter]::GetBytes([uint32]($generatedImageBytes - 0x2000))
    $sourceHandle.Write($virtualBytes, 0, 4)
} finally { $sourceHandle.Dispose() }
$generatedHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()

function Get-Hash([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-SubmittedBinding([string]$Run, [object]$Receipt) {
    $requestPath = Join-Path $Run 'request.json'
    $inputPath = Join-Path $Run 'input.sys'
    $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
    $manifest = Get-Content -LiteralPath (Join-Path $Run 'controller-manifest.json') -Raw | ConvertFrom-Json
    $ready = Get-Content -LiteralPath (Join-Path $Run 'worker-ready.json') -Raw | ConvertFrom-Json
    $result = Get-Content -LiteralPath (Join-Path $Run 'worker-result.json') -Raw | ConvertFrom-Json
    $requestHash = Get-Hash $requestPath
    $inputHash = Get-Hash $inputPath
    $inputSize = (Get-Item -LiteralPath $inputPath).Length
    if ($requestHash -cne $manifest.request_sha256 -or $requestHash -cne $ready.request_sha256 -or
        $requestHash -cne $result.binding.request_sha256 -or
        $inputHash -cne $request.input_sha256 -or $inputHash -cne $manifest.input_sha256 -or
        $inputHash -cne $ready.input_sha256 -or $inputHash -cne $result.binding.input_sha256 -or
        $inputSize -ne $request.input_size -or $inputSize -ne $ready.input_size -or
        $request.run_id -cne $manifest.run_id -or $request.run_id -cne $ready.run_id -or
        $request.service_name -cne $manifest.service_name -or $request.service_name -cne $ready.service_name -or
        $ready.source_tree_sha256 -cne $Receipt.source_tree_sha256 -or
        $manifest.source_tree_sha256 -cne $Receipt.source_tree_sha256) {
        throw 'Submitted request/input evidence binding differs'
    }
}
function Assert-ContainedCleanup([string]$Run) {
    $witness = Get-Content -LiteralPath (Join-Path $Run 'worker-containment.json') -Raw | ConvertFrom-Json
    $job = Get-Content -LiteralPath (Join-Path $Run 'driver-job-profile.json') -Raw | ConvertFrom-Json
    $stop = Get-Content -LiteralPath (Join-Path $Run 'worker-stop.json') -Raw | ConvertFrom-Json
    $exit = Get-Content -LiteralPath (Join-Path $Run 'worker-exit.json') -Raw | ConvertFrom-Json
    if ($witness.app_container -ne $true -or $witness.job_object -ne $true -or
        $witness.child_process_blocked -ne $true -or $witness.network_capabilities -ne 0 -or
        $job.profile -cne 'driver_capture_2048_v1' -or $job.process_memory_bytes -ne 2147483648 -or
        $job.active_process_limit -ne 1 -or $job.network_capabilities -ne 0 -or
        $job.peak_process_memory_bytes -le 0 -or $job.peak_process_memory_bytes -gt 2147483648 -or
        $job.cleanup -cne 'restored' -or $stop.cleanup -cne 'restored' -or
        $exit.cleanup -cne 'restored' -or $stop.worker.reason -cne 'exited' -or
        $stop.worker.exit_code -ne $exit.exit_code) {
        throw 'Submitted offline AppContainer/job or cleanup evidence differs'
    }
    return $exit.exit_code
}

& $cli submitted-driver $source $submitted --service TestDrv --max-instructions 1000 --timeout-us 30000000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Submitted generated driver did not complete' }
$manifest = Get-Content -LiteralPath (Join-Path $submitted 'controller-manifest.json') -Raw | ConvertFrom-Json
$ready = Get-Content -LiteralPath (Join-Path $submitted 'worker-ready.json') -Raw | ConvertFrom-Json
$engine = Get-Content -LiteralPath (Join-Path $submitted 'engine-report.json') -Raw | ConvertFrom-Json
$summary = Get-Content -LiteralPath (Join-Path $submitted 'summary.json') -Raw | ConvertFrom-Json
$worker = Get-Content -LiteralPath (Join-Path $submitted 'worker-result.json') -Raw | ConvertFrom-Json
$receipt = Get-Content -LiteralPath (Join-Path $BundleDirectory 'rust-worker-build.json') -Raw | ConvertFrom-Json
Assert-SubmittedBinding $submitted $receipt
if ((Assert-ContainedCleanup $submitted) -ne 0 -or $manifest.cleanup -cne 'restored') { throw 'Submitted worker success cleanup differs' }
if ($manifest.controller_sha256 -cne (Get-Hash $cli) -or
    $manifest.worker_sha256 -cne (Get-Hash (Join-Path $BundleDirectory 'emumee-worker.exe')) -or
    $manifest.unicorn_sha256 -cne (Get-Hash (Join-Path $BundleDirectory 'unicorn.dll')) -or
    $manifest.controller_sha256 -cne $receipt.controller_sha256 -or
    $manifest.worker_sha256 -cne $receipt.worker_sha256 -or
    $manifest.unicorn_sha256 -cne $receipt.unicorn_sha256 -or
    $manifest.worker_result_sha256 -cne (Get-Hash (Join-Path $submitted 'worker-result.json'))) {
    throw 'Packaged binary/result hash binding differs'
}
if ($manifest.status -ne 'verified' -or $manifest.guest_status -ne 'processed') { throw 'Submitted role was not verified' }
if ($manifest.input_sha256 -ne $generatedHash -or $ready.input_sha256 -ne $generatedHash) { throw 'Generated source binding differs' }
if ($manifest.source_tree_sha256 -ne $receipt.source_tree_sha256 -or $ready.source_tree_sha256 -ne $receipt.source_tree_sha256) { throw 'Packaged source binding differs' }
if ($ready.driver_name -ne '\Driver\TestDrv' -or $ready.registry_path -ne '\Registry\Machine\System\CurrentControlSet\Services\TestDrv') { throw 'Caller service identity differs' }
if ($engine.mode -ne 'submitted_driver_capture') { throw 'Typed submitted Driver128 mode missing' }
if ($engine.execution.kernel_entry.registry_name -ne $ready.registry_path) { throw 'Guest DriverEntry registry argument differs' }
if ($engine.execution.completion_reason -ne 'entry_return' -or $engine.execution.guest_entry_return -ne 17) { throw 'Generated DriverEntry execution differs' }
$capture = $engine.execution.capture_runtime
if ($null -eq $capture -or $capture.profile -ne 'driver128_v1' -or $capture.input_sha256 -ne $generatedHash) { throw 'Submitted capture receipt/input binding missing' }
if ($capture.boundary_instructions -ne $engine.execution.instruction_count -or $capture.boundary_pc -ne $engine.execution.final_pc) { throw 'Settled capture boundary differs from execution' }
if (-not $capture.selected_read_complete -or $capture.post_image_sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Selected settled image read did not complete' }
if (@($capture.markers).Count -ne 0) { throw 'Submitted capture used a generated marker oracle' }
$settled = @($summary.artifacts | Where-Object {
    $_.sha256 -eq $capture.post_image_sha256 -and $_.size -eq $capture.image_bytes -and
    @($_.observations | Where-Object {
        $_.kind -eq 'memory_snapshot' -and $_.source -eq 'settled_root_image' -and
        $_.context.capture_boundary -eq 'settled' -and $_.context.guest_base -eq $capture.image_base -and
        $_.context.layout -eq 'mapped_image' -and $_.context.image_size -eq $capture.image_bytes
    }).Count -gt 0
})
if ($settled.Count -ne 1) { throw 'Settled root snapshot is absent or not bound to the receipt' }
if ($manifest.capture_status -ne $summary.summary.status -or $manifest.driver_summary_sha256 -ne (Get-FileHash -LiteralPath (Join-Path $submitted 'summary.json') -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Parent typed Driver128 summary binding differs' }
if ($worker.capture_omitted_observations -ne $engine.execution.capture_summary.omitted_observations) { throw 'Capture omissions differ between worker and execution' }
& $cli inspect-driver-capture $submitted | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Parent-authored typed Driver128 documents/payloads failed inspection' }
if ($manifest.unpacking_confirmed -ne $false) { throw 'Generated fixture cannot certify unpacking' }
if ($worker.unpacking_confirmed -ne $false -or
    @($summary.artifacts | Where-Object { @($_.observations | Where-Object { $_.kind -eq 'unpacked_driver' }).Count -gt 0 }).Count -ne 0) {
    throw 'A raw generated capture was labelled unpacked'
}

# Negative control: a copied, generated-only output with one captured byte
# changed must fail the same typed, safe-pinned Driver128 reader.
$tampered = Join-Path $root 'tampered-submitted-output'
Copy-Item -LiteralPath $submitted -Destination $tampered -Recurse
$payload = Join-Path (Join-Path $tampered 'artifacts') $settled[0].filename
$handle = [System.IO.File]::Open($payload, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try {
    $before = $handle.ReadByte()
    if ($before -lt 0) { throw 'Generated settled payload is empty' }
    $handle.Position = 0
    $handle.WriteByte([byte]($before -bxor 1))
} finally { $handle.Dispose() }
& $cli inspect-driver-capture $tampered 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { throw 'Tampered generated payload was accepted by typed reader' }

$tamperedReport = Join-Path $root 'tampered-submitted-report'
Copy-Item -LiteralPath $submitted -Destination $tamperedReport -Recurse
$enginePath = Join-Path $tamperedReport 'engine-report.json'
$engineText = [System.IO.File]::ReadAllText($enginePath)
$changed = $engineText.Replace('driver128_v1', 'driver128_x1')
if ($changed -eq $engineText) { throw 'Generated engine profile token missing' }
[System.IO.File]::WriteAllText($enginePath, $changed, [System.Text.UTF8Encoding]::new($false))
& $cli inspect-driver-capture $tamperedReport 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { throw 'Tampered generated engine report was accepted by typed reader' }

# A harmless generated PE with an intentionally over-profile mapped image
# must be refused before a guest result can be interpreted as evidence.
$oversizedSource = Join-Path $root 'OversizedGenerated.sys'
$oversizedBytes = [System.IO.File]::ReadAllBytes($source)
$sizeBytes = [System.BitConverter]::GetBytes([uint32](128 * 1024 * 1024 + 4096))
[System.Array]::Copy($sizeBytes, 0, $oversizedBytes, 0x98 + 56, 4)
[System.IO.File]::WriteAllBytes($oversizedSource, $oversizedBytes)
$oversizedRun = Join-Path $root 'oversized-generated-refusal'
& $cli submitted-driver $oversizedSource $oversizedRun --service OversizedGenerated --max-instructions 1000 --timeout-us 30000000 | Out-Null
$oversizedCliExit = $LASTEXITCODE
$oversizedManifest = Get-Content -LiteralPath (Join-Path $oversizedRun 'controller-manifest.json') -Raw | ConvertFrom-Json
$oversizedResult = Get-Content -LiteralPath (Join-Path $oversizedRun 'worker-result.json') -Raw | ConvertFrom-Json
Assert-SubmittedBinding $oversizedRun $receipt
if ((Assert-ContainedCleanup $oversizedRun) -ne 0 -or $oversizedCliExit -eq 0 -or
    $oversizedManifest.status -cne 'verified_refusal' -or $oversizedManifest.guest_status -cne 'unreported_failure' -or
    $oversizedManifest.cleanup -cne 'restored' -or $oversizedManifest.unpacking_confirmed -ne $false -or
    $oversizedManifest.artifacts_verified -ne 0 -or $oversizedManifest.artifact_bytes_verified -ne 0 -or
    $oversizedManifest.worker_result_sha256 -cne (Get-Hash (Join-Path $oversizedRun 'worker-result.json')) -or
    $oversizedResult.status -cne 'unreported_failure' -or
    $null -ne $oversizedResult.PSObject.Properties['unpacking_confirmed'] -or
    $oversizedResult.error -cnotlike '*Runtime capture target exceeds the bounded driver profile*' -or
    (Test-Path -LiteralPath (Join-Path $oversizedRun 'worker-error.txt')) -or
    (Test-Path -LiteralPath (Join-Path $oversizedRun 'engine-report.json')) -or
    (Test-Path -LiteralPath (Join-Path $oversizedRun 'worker-summary.json')) -or
    (Test-Path -LiteralPath (Join-Path $oversizedRun 'summary.json')) -or
    (Test-Path -LiteralPath (Join-Path $oversizedRun 'artifacts'))) {
    throw 'Oversized generated image lacked a bound contained capture-profile refusal'
}

foreach ($case in @(
    @{ name = 'path'; service = '..\escape' },
    @{ name = 'leading-digit'; service = '1TestDrv' },
    @{ name = 'overlong'; service = ('A' * 65) }
)) {
    $invalidRoot = Join-Path $root ('invalid-service-' + $case.name)
    & $cli submitted-driver $source $invalidRoot --service $case.service 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $invalidRoot)) {
        throw "Invalid service crossed request admission: $($case.name)"
    }
}

# These controls change saved generated evidence and verify exact binding.
# They do not inject a race into a running AppContainer worker.
foreach ($name in @('request', 'input')) {
    $copy = Join-Path $root "tampered-$name-binding"
    [System.IO.Directory]::CreateDirectory($copy) | Out-Null
    foreach ($part in @('request.json', 'input.sys', 'worker-ready.json', 'worker-result.json', 'controller-manifest.json')) {
        Copy-Item -LiteralPath (Join-Path $submitted $part) -Destination (Join-Path $copy $part)
    }
    if ($name -eq 'request') {
        $changed = Get-Content -LiteralPath (Join-Path $copy 'request.json') -Raw | ConvertFrom-Json
        $changed.service_name = 'OtherDrv'
        [System.IO.File]::WriteAllText((Join-Path $copy 'request.json'), ($changed | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))
    } else {
        $target = Join-Path $copy 'input.sys'
        $handle = [System.IO.File]::Open($target, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            if ($handle.Length -eq 0) { throw 'Generated submitted input is empty' }
            $before = $handle.ReadByte()
            $handle.Position = 0
            $handle.WriteByte([byte]($before -bxor 1))
        } finally { $handle.Dispose() }
    }
    $rejected = $false
    try { Assert-SubmittedBinding $copy $receipt } catch { $rejected = $true }
    if (-not $rejected) { throw "Tampered $name evidence retained its source/request binding" }
}

# Malformed generated bytes reach the packaged offline worker. It must record
# an error and the parent must restore the AppContainer/job grants.
$badSource = Join-Path $root 'generated-invalid-pe.sys'
Copy-Item -LiteralPath $source -Destination $badSource
$handle = [System.IO.File]::Open($badSource, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try {
    if ($handle.Length -eq 0) { throw 'Generated driver is empty' }
    $before = $handle.ReadByte()
    $handle.Position = 0
    $handle.WriteByte([byte]($before -bxor 1))
} finally { $handle.Dispose() }
$badRun = Join-Path $root 'invalid-pe-worker-error'
& $cli submitted-driver $badSource $badRun --service TestDrv --max-instructions 1000 --timeout-us 30000000 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { throw 'Malformed generated PE was accepted' }
$badManifest = Get-Content -LiteralPath (Join-Path $badRun 'controller-manifest.json') -Raw | ConvertFrom-Json
$badExit = Assert-ContainedCleanup $badRun
$badError = Get-Content -LiteralPath (Join-Path $badRun 'worker-error.txt') -Raw
if ($badExit -ne 2 -or $badManifest.status -cne 'failed' -or $badManifest.unpacking_confirmed -ne $false -or
    $badManifest.input_sha256 -cne (Get-Hash $badSource) -or
    $badManifest.request_sha256 -cne (Get-Hash (Join-Path $badRun 'request.json')) -or
    $badError -cnotlike '*missing DOS signature*' -or
    (Test-Path -LiteralPath (Join-Path $badRun 'worker-ready.json')) -or
    (Test-Path -LiteralPath (Join-Path $badRun 'worker-result.json')) -or
    (Test-Path -LiteralPath (Join-Path $badRun 'engine-report.json')) -or
    (Test-Path -LiteralPath (Join-Path $badRun 'worker-summary.json')) -or
    (Test-Path -LiteralPath (Join-Path $badRun 'artifacts\manifest.json'))) {
    throw 'Malformed generated PE did not preserve worker error, cleanup and no-report evidence'
}

[pscustomobject]@{
    schema = 1
    role = 'generated_submitted_driver_qualification'
    closed_recipe_sha256 = $closedRecipeHash
    source_sha256 = $generatedHash
    source_tree_sha256 = $receipt.source_tree_sha256
    submitted_run = $submitted
    guest_completion = $engine.execution.completion_reason
    guest_entry_return = $engine.execution.guest_entry_return
    settled_boundary = $capture.boundary_pc
    settled_sha256 = $capture.post_image_sha256
    typed_driver128_verified = $true
    tampered_payload_refused = $true
    tampered_report_refused = $true
    oversized_generated_refused = $true
    invalid_service_refused = $true
    request_tamper_binding_refused = $true
    input_tamper_binding_refused = $true
    malformed_generated_worker_refused = $true
    malformed_worker_cleanup_restored = $true
    unpacking_confirmed = $false
} | ConvertTo-Json -Depth 5
exit 0
