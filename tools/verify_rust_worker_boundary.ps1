param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve previous worker boundary evidence; choose a fresh root.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
    @{name='normal';reason='exited';exit=0;success=$true},
    @{name='timeout';reason='timeout';exit=1},
    @{name='output-bytes';reason='output_limit';exit=1;dimension='bytes'},
    @{name='output-count';reason='output_limit';exit=1;dimension='entries'},
    @{name='file-stream';reason='output_limit';exit=1;dimension='bytes';streams=1},
    @{name='directory-stream';reason='output_limit';exit=1;dimension='bytes';streams=1},
    @{name='fast-output';reason='output_limit';exit=@(0,1);dimension='bytes'},
    @{name='output-link';reason='output_inspection_failed';exit=1},
    @{name='abrupt-exit';reason='exited';exit=23}
)
$records=@()
foreach($case in $cases) {
    $run=Join-Path $root $case.name
    & (Join-Path $bundlePath 'emumee-rs.exe') boundary-probe $case.name $run *> ($run+'.console.log')
    $exit=$LASTEXITCODE
    if(($case.success -and $exit -ne 0) -or (-not $case.success -and $exit -eq 0)){throw "Incorrect parent status for $($case.name)."}
    $ready=Get-Content -LiteralPath (Join-Path $run 'worker-ready.json') -Raw | ConvertFrom-Json
    if(-not $ready.app_container -or -not $ready.job_object -or -not $ready.child_process_blocked -or $ready.network_capabilities -ne 0){throw 'Fault probe did not verify offline containment.'}
    $stop=Get-Content -LiteralPath (Join-Path $run 'worker-stop.json') -Raw | ConvertFrom-Json
    if($stop.cleanup -ne 'restored' -or $stop.worker.reason -ne $case.reason -or @($case.exit) -notcontains $stop.worker.exit_code -or $stop.worker.output_checks -lt 1){throw "Incorrect verified worker stop for $($case.name)."}
    if($case.dimension -and $stop.worker.detail -notlike "*exceeds $($case.dimension) limit*"){throw 'Output refusal has the wrong cause.'}
    if($case.streams -and $stop.worker.output_usage.named_streams -ne $case.streams){throw 'Named output stream was not counted.'}
    if($case.name -eq 'timeout' -and ($stop.worker.elapsed_ms -lt 1000 -or $stop.worker.elapsed_ms -gt 8000)){throw 'Timeout did not use the parent wall-clock deadline.'}
    $manifest=Join-Path $run 'manifest.json'
    if($case.success) {
        $result=Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        if($result.result.execution.guest_entry_return -ne 10 -or $result.result.execution.completion_reason -ne 'entry_return'){throw 'Normal probe did not preserve guest execution.'}
    } elseif(Test-Path -LiteralPath $manifest) {throw 'Failed probe was labeled as a qualified run.'}
    $records+=@{case=$case.name;reason=$stop.worker.reason;worker_exit=$stop.worker.exit_code;parent_exit=$exit;output_usage=$stop.worker.output_usage;output_checks=$stop.worker.output_checks;elapsed_ms=$stop.worker.elapsed_ms;cleanup=$stop.cleanup;verified=$true}
}
$records | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) isolated worker boundary controls."
$global:LASTEXITCODE=0
