param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Use a fresh native smoke root.'}
$null=New-Item -ItemType Directory -Path $root
$records=@()
foreach($arch in @('x86','x64')) {
    foreach($budget in @(10000,32)) {
        $run=Join-Path $root ($arch+'-'+$budget)
        & (Join-Path $bundlePath 'emumee-rs.exe') fixture --arch $arch --iterations 1000 --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
        $exit=$LASTEXITCODE
        $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw | ConvertFrom-Json
        $e=$result.execution
        if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Native smoke containment failure.'}
        if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -ne $e.error){throw 'Native dispatcher/backend changed.'}
        if($budget -eq 32) {
            if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne 32 -or $null -ne $e.guest_entry_return){throw 'Native instruction budget changed.'}
        } else {
            if($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.instruction_count -ne 3003 -or $e.guest_entry_return -ne 1000){throw 'Native counted-loop result changed.'}
        }
        $records+=@{arch=$arch;budget=$budget;instructions=$e.instruction_count;completion=$e.completion_reason;return=$e.guest_entry_return;verified=$true}
    }
}
$records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) isolated native smoke cases; full API baseline is separate."
