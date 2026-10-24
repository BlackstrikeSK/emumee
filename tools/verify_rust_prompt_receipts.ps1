param(
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [switch]$Resume,
    [switch]$Continuation
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$bundlePath = [IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$root = [IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
$exe = Join-Path $bundlePath 'emumee-rs.exe'
if (Test-Path -LiteralPath $root) {
    if (-not $Resume) { throw 'Preserve prompt evidence; choose a fresh root or explicit Resume.' }
} else { $null = New-Item -ItemType Directory -Path $root }
function Read-Json([string]$Path) {
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$receipt = Read-Json (Join-Path $bundlePath 'rust-worker-build.json')
foreach ($item in @(
    @{file='emumee-rs.exe'; key='controller_sha256'},
    @{file='emumee-worker.exe'; key='worker_sha256'},
    @{file='unicorn.dll'; key='unicorn_sha256'}
)) {
    if ((Get-Sha256 (Join-Path $bundlePath $item.file)) -cne $receipt.($item.key)) {
        throw 'Frozen prompt-control binary differs from its build receipt.'
    }
}
$records = @()
foreach ($arch in @('x86','x64')) {
    foreach ($kind in @('debug-prompt','prompt-to-code')) {
        $run = Join-Path $root ($arch + '-' + $kind)
        $reused = Test-Path -LiteralPath $run
        if ($reused) {
            if (-not $Resume) { throw 'Never overwrite an existing prompt control.' }
        } else {
            & $exe fixture --arch $arch --kind $kind --max-instructions 10000 --isolated-output $run *> ($run + '.console.log')
            $exit = $LASTEXITCODE
        }
        $manifest = Read-Json (Join-Path $run 'manifest.json')
        $console = Read-Json ($run + '.console.log')
        if (($console | ConvertTo-Json -Depth 100 -Compress) -cne ($manifest | ConvertTo-Json -Depth 100 -Compress)) {
            throw 'Prompt controller stdout differs from its saved manifest.'
        }
        $requestPath = Join-Path $run 'request.json'
        $request = Read-Json $requestPath
        $requestHash = Get-Sha256 $requestPath
        $resultPath = Join-Path $run 'fixture-result.json'
        $result = Read-Json $resultPath
        $resultHash = Get-Sha256 $resultPath
        $workerExit = Read-Json (Join-Path $run 'worker-exit.json')
        foreach ($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')) {
            if ($manifest.$key -cne $receipt.$key) { throw 'Prompt run belongs to another frozen build.' }
        }
        if ($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or
            $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or
            $result.request_sha256 -cne $requestHash -or $request.kind -ne $kind -or
            $request.architecture -ne $arch -or $request.max_instructions -ne 10000) {
            throw 'Prompt request/result/build/cleanup binding failed.'
        }
        if (($manifest.result | ConvertTo-Json -Depth 100 -Compress) -cne ($result | ConvertTo-Json -Depth 100 -Compress)) {
            throw 'Prompt manifest result differs from the bound worker result.'
        }
        if (-not $result.containment.app_container -or -not $result.containment.job_object -or
            -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0) {
            throw 'Prompt control lacks offline AppContainer containment.'
        }
        $e = $result.execution
        if ($reused) { $exit = if ($e.completion_reason -eq 'entry_return') { 0 } else { 1 } }
        if ($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $e.api_calls -ne $(if ($arch -eq 'x64') { 3 } else { 1 }) -or
            @($e.api_events).Count -ne $(if ($arch -eq 'x64') { 3 } else { 1 }) -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or
            $null -eq $e.kernel_cpu -or $null -eq $e.kernel_entry -or $null -eq $e.kernel_prompt) {
            throw 'Prompt native/kernel/API report differs from the closed fixture.'
        }
        if ($arch -eq 'x64') {
            $api = $e.api_events[0]
            $prompt = $e.kernel_prompt
            $native = $e.native_exceptions
            $base = [decimal]$e.image_load.base
            $response = $base + $(if ($kind -eq 'prompt-to-code') { 0x1000 } else { 0x2b40 })
            if ($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 0x52525252 -or
                $null -ne $e.error -or $null -ne $api.error -or $null -ne $api.result -or $api.pending -or
                $api.effect -ne 'raised_native_exception' -or $api.api -ne 'ntoskrnl.DbgPrompt' -or
                $prompt.input_policy -ne 'no_debugger_exception' -or $prompt.response_writes -ne 0 -or
                $prompt.calls -ne 1 -or $prompt.omitted -ne 0 -or @($prompt.observations).Count -ne 1 -or
                @($api.arguments).Count -ne 3 -or [decimal]$api.arguments[0] -ne ($base + 0x2b00) -or
                [decimal]$api.arguments[1] -ne $response -or $api.arguments[2] -ne 32) {
                throw 'AMD64 prompt did not raise/catch the no-debugger exception with unchanged response.'
            }
            $row = $prompt.observations[0]
            if ($row.prompt -cne 'Rust no input?' -or $row.prompt_bytes -ne 14 -or $row.preview_truncated -or
                $row.length -ne 32 -or $row.effective_response_capacity -ne 32 -or $null -ne $row.result -or
                $row.exception_code -ne 0x80000003L -or $row.response_writes -ne 0 -or $row.received_characters -ne 0 -or
                ($row.arguments | ConvertTo-Json -Compress) -cne ($api.arguments | ConvertTo-Json -Compress)) {
                throw 'AMD64 prompt receipt fabricated a normal return or debugger input.'
            }
            foreach ($key in @('api_gate_pc','instruction_ordinal','thread_id','current_thread','processor','execution_domain')) {
                if ($row.$key -ne $api.$key) { throw "AMD64 prompt/API metadata differs at $key." }
            }
            $fault = $native.events[0]
            $frame = $native.api_exceptions[0]
            if ($native.exceptions_raised -ne 1 -or $native.unwinds_completed -ne 1 -or $native.active -or $native.pending -or
                @($native.api_exceptions).Count -ne 1 -or -not $frame.delivered -or $frame.kind -ne 'Prompt' -or
                $fault.code -ne 0x80000003L -or @($fault.parameters).Count -ne 1 -or $fault.parameters[0] -ne 2 -or
                [decimal]$fault.exception_address -ne ([decimal]$frame.fault_site + 1) -or
                [decimal]$frame.gate -ne [decimal]$api.api_gate_pc -or
                @($e.api_events | Where-Object { $_.api -eq 'ntoskrnl.__C_specific_handler' }).Count -ne 2) {
                throw 'AMD64 prompt search/unwind evidence differs from its owned trap frame.'
            }
            if ($Continuation) {
                $window = $prompt.continuation
                $snapshots = @($window.instructions)
                if ($window.active -or $window.truncated -or $window.stop.reason -ne 'next_api_gate' -or
                    $window.first_prompt_ordinal -ne $row.instruction_ordinal -or $snapshots.Count -ne 1 -or
                    [decimal]$snapshots[0].pc -ne ($base + 0x1a00) -or
                    $snapshots[0].instruction_ordinal -ne $row.instruction_ordinal -or
                    $window.stop.pc -ne $e.api_events[1].api_gate_pc) {
                    throw 'AMD64 prompt continuation is not the actual guest exception wrapper.'
                }
            }
            $records += @{arch=$arch; kind=$kind; verified=$true; reused=[bool]$reused;
                source_tree_sha256=$receipt.source_tree_sha256; request_sha256=$requestHash; result_sha256=$resultHash;
                completion=$e.completion_reason; instructions=$e.instruction_count; response_writes=0;
                exception_code='80000003'; service=2; normal_api_return=$false;
                cleanup='restored'; unpacking_confirmed=$false}
            $records | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
            continue
        }
        $api = $e.api_events[0]
        $prompt = $e.kernel_prompt
        $negative = $kind -eq 'prompt-to-code'
        $base = [decimal]$e.image_load.base
        $response = $base + $(if ($negative) { 0x1000 } else { 0x2b40 })
        if ($api.api -ne 'ntoskrnl.DbgPrompt' -or $api.arguments.Count -ne 3 -or
            [decimal]$api.arguments[0] -ne ($base + 0x2b00) -or [decimal]$api.arguments[1] -ne $response -or
            $api.arguments[2] -ne 32 -or $api.pending -or $api.last_error -ne 0 -or
            $prompt.input_policy -ne $(if ($negative) { 'not_observed' } else { 'legacy_x86_no_input' }) -or $prompt.response_writes -ne 0 -or $prompt.omitted -ne 0) {
            throw 'Prompt arguments, input policy or write accounting changed.'
        }
        if ($negative) {
            if ($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or
                $e.error -notmatch 'lacks permission' -or $api.error -notmatch 'lacks permission' -or
                $null -ne $api.result -or $prompt.calls -ne 0 -or @($prompt.observations).Count -ne 0) {
                throw 'Denied prompt response write invented a successful receipt or continuation.'
            }
        } else {
            if ($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 0x52525252 -or
                $null -ne $e.error -or $null -ne $api.error -or $api.result -ne 0 -or
                $prompt.calls -ne 1 -or @($prompt.observations).Count -ne 1) {
                throw 'Prompt no-input result or unchanged response marker differs.'
            }
            $row = $prompt.observations[0]
            if ($row.prompt -cne 'Rust no input?' -or $row.prompt_bytes -ne 14 -or $row.preview_truncated -or
                $row.length -ne 32 -or $row.received_characters -ne 0 -or $row.result -ne 0 -or
                $row.response_writes -ne 0 -or [decimal]$row.prompt_address -ne [decimal]$api.arguments[0] -or
                [decimal]$row.response_address -ne [decimal]$api.arguments[1] -or
                ($row.arguments | ConvertTo-Json -Compress) -cne ($api.arguments | ConvertTo-Json -Compress)) {
                throw 'Successful prompt text, argument or zero-effect receipt differs.'
            }
            foreach ($key in @('api_gate_pc','instruction_ordinal','thread_id','current_thread','processor','execution_domain')) {
                if ($row.$key -ne $api.$key) { throw "Prompt/API metadata differs at $key." }
            }
            $history = @($row.recent_instructions)
            $tail = @($e.instruction_tail)
            # These tiny fixtures retain their complete chronological history.
            # The receipt precedes the current immutable API gate's RET; that
            # gate is not required to appear in the saved recent history.
            if ($history.Count -lt 1 -or $history.Count -gt 32 -or $e.instruction_count -ne $tail.Count -or
                $row.instruction_ordinal -lt $history.Count -or $row.instruction_ordinal -gt $tail.Count) {
                throw 'Prompt recent-instruction bounds or full fixture history differ.'
            }
            $start = [int]$row.instruction_ordinal - $history.Count
            for ($i = 0; $i -lt $history.Count; $i++) {
                $actual = $history[$i]
                $expected = $tail[$start + $i]
                if ([decimal]$actual.pc -ne [decimal]$expected.pc -or $actual.size -ne $expected.size -or
                    $actual.size -lt 1 -or $actual.size -gt 15 -or
                    ([decimal]$actual.pc -ge [decimal]$e.api_region.base -and
                     [decimal]$actual.pc -lt ([decimal]$e.api_region.base + [decimal]$e.api_region.size))) {
                    throw 'Prompt recent history differs from real chronological pre-gate instructions.'
                }
            }
        }
        if ($Continuation) {
            $window = $prompt.continuation
            if ($negative) {
                if ($null -ne $window) { throw 'Refused prompt opened a continuation trace.' }
            } else {
                $order = @($window.register_order)
                $expectedOrder = if ($arch -eq 'x64') {
                    @('rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15','eflags')
                } else { @('eax','ebx','ecx','edx','esi','edi','ebp','esp','eflags') }
                $snapshots = @($window.instructions)
                if ($null -eq $window -or $window.architecture -ne $arch -or
                    ($order -join ',') -cne ($expectedOrder -join ',') -or
                    $window.first_prompt_ordinal -ne $row.instruction_ordinal -or $window.limit -ne 32768 -or
                    $window.active -or -not $window.truncated -or $window.stop.reason -ne 'run_stopped' -or
                    $window.stop.run_completion -ne 'entry_return' -or $null -ne $window.stop.error -or
                    $window.stop.instruction_ordinal -ne $e.instruction_count -or
                    $snapshots.Count -lt 2 -or $snapshots.Count -gt $window.limit -or
                    $snapshots[0].instruction_ordinal -ne ($row.instruction_ordinal + 1) -or
                    $snapshots[0].registers[0] -ne 0 -or $snapshots[-1].registers[0] -ne 0x52525252) {
                    throw 'Prompt continuation bounds, pre-instruction registers or stop accounting differs.'
                }
                foreach ($snapshot in $snapshots) {
                    $actualInstruction = $tail[[int]$snapshot.instruction_ordinal]
                    if (@($snapshot.registers).Count -ne $order.Count -or
                        [decimal]$snapshot.pc -ne [decimal]$actualInstruction.pc -or
                        $snapshot.size -ne $actualInstruction.size -or $snapshot.size -lt 1 -or $snapshot.size -gt 15 -or
                        $snapshot.thread_id -ne $api.thread_id -or $snapshot.current_thread -ne $api.current_thread -or
                        $snapshot.processor -ne $api.processor -or $snapshot.execution_domain -ne $api.execution_domain -or
                        ([decimal]$snapshot.pc -ge [decimal]$e.api_region.base -and
                         [decimal]$snapshot.pc -lt ([decimal]$e.api_region.base + [decimal]$e.api_region.size))) {
                        throw 'Prompt continuation contains an API gate or mismatches actual native fixture history.'
                    }
                }
            }
        }
        $records += @{arch=$arch; kind=$kind; verified=$true; reused=[bool]$reused;
            source_tree_sha256=$receipt.source_tree_sha256; request_sha256=$requestHash; result_sha256=$resultHash;
            completion=$e.completion_reason; instructions=$e.instruction_count; response_writes=0;
            cleanup='restored'; unpacking_confirmed=$false}
        $records | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
    }
}
if ($records.Count -ne 4) { throw 'Prompt control count differs.' }
Write-Output 'Verified four generated prompt controls: AMD64 no-debugger exception/catch and opaque response; legacy x86 no-input/denial, with frozen build binding and offline containment.'
$global:LASTEXITCODE = 0
