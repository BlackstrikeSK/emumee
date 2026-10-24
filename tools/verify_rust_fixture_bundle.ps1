param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $workspace
$bundlePath=(Resolve-Path -LiteralPath $Bundle).Path
$outputPath=[System.IO.Path]::GetFullPath((Join-Path $workspace $OutputRoot))
if(Test-Path -LiteralPath $outputPath){throw 'Preserve existing qualification evidence.'}
New-Item -ItemType Directory -Path $outputPath | Out-Null
$rows=@()
foreach($file in @('emumee-worker.exe','unicorn.dll')) {
    $case=Join-Path $outputPath ($file.Replace('.','-'))
    New-Item -ItemType Directory -Path $case | Out-Null
    $copy=Join-Path $case 'bundle'
    Copy-Item -LiteralPath $bundlePath -Destination $copy -Recurse
    $target=Join-Path $copy $file
    $data=[System.IO.File]::ReadAllBytes($target)
    $data[$data.Length-1]=$data[$data.Length-1] -bxor 1
    [System.IO.File]::WriteAllBytes($target,$data)
    $run=Join-Path $case 'must-not-run'
    $start=[System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName=Join-Path $copy 'emumee-rs.exe'
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardError=$true;$start.RedirectStandardOutput=$true
    foreach($argument in @('fixture','--iterations','10','--isolated-output',$run)){$start.ArgumentList.Add($argument)}
    $process=[System.Diagnostics.Process]::Start($start)
    $stdout=$process.StandardOutput.ReadToEnd();$stderr=$process.StandardError.ReadToEnd();$process.WaitForExit()
    [System.IO.File]::WriteAllText((Join-Path $case 'stdout.txt'),$stdout)
    [System.IO.File]::WriteAllText((Join-Path $case 'stderr.txt'),$stderr)
    if($process.ExitCode -eq 0 -or (Test-Path -LiteralPath $run)){throw "Tampered $file reached worker execution."}
    if($stderr -notmatch 'differs from its receipt'){throw "Tampered $file did not reach the intended integrity refusal: $stderr"}
    $rows+=@{case=$file;verified=$true;exit_code=$process.ExitCode;guest_execution_prevented=$true}
}
$rows | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputPath 'verification.json') -Encoding utf8NoBOM
Write-Output 'Rust worker and CPU-library tampering rejected before launch.'
