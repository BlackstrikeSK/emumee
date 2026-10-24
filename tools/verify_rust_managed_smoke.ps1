param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Use a fresh managed smoke root.'}
$null=New-Item -ItemType Directory -Path $root
$records=@()
foreach($arch in @('x86','x64')) {
    foreach($budget in @(10000,70)) {
        $run=Join-Path $root ($arch+'-'+$budget)
        & $exe fixture --kind managed-rva-decode --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
        $exit=$LASTEXITCODE
        $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw | ConvertFrom-Json
        $e=$result.execution
        if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0 -or $e.backend -ne 'rust/managed-il' -or $null -ne $e.error){throw 'Managed smoke containment/backend failure.'}
        if($budget -eq 70) {
            if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne 70 -or $null -ne $e.guest_entry_return -or $e.artifacts.Count -ne 0){throw 'Managed smoke partial run changed.'}
        } else {
            if($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.instruction_count -ne 75 -or $e.guest_entry_return -ne 82 -or $e.artifacts.Count -ne 1){throw 'Managed smoke decode result changed.'}
            $artifact=$e.artifacts[0]
            $bytes=[IO.File]::ReadAllBytes((Join-Path (Join-Path $run 'artifacts') $artifact.filename))
            if([Text.Encoding]::ASCII.GetString($bytes) -ne 'RUST' -or (Get-FileHash -LiteralPath (Join-Path (Join-Path $run 'artifacts') $artifact.filename)).Hash.ToLowerInvariant() -ne $artifact.sha256){throw 'Managed smoke artifact changed.'}
        }
        $records+=@{arch=$arch;budget=$budget;completion=$e.completion_reason;instructions=$e.instruction_count;return=$e.guest_entry_return;artifacts=$e.artifacts.Count;verified=$true}
    }
}
$records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output 'Verified 4 isolated managed decode/artifact smoke cases; full IL baseline is separate.'
