# Kill only the exact broker started for this harmless packaged CLI run.
$workspace = (Resolve-Path .).Path
$exe = (Resolve-Path .\dist\Emumee\Emumee.exe).Path
$output = Join-Path $workspace ('output\cli-broker-kill-' + [guid]::NewGuid().ToString('N'))
$sample = 'tests\fixtures\ManagedGzip\bin\Release\net8.0\ManagedGzip.dll'
$cli = Start-Process -FilePath $exe -ArgumentList @('run', $sample, '--output', $output) `
    -WorkingDirectory $workspace -WindowStyle Hidden -PassThru
try {
    $deadline = (Get-Date).AddSeconds(12)
    $run = $null
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $output) {
            $run = Get-ChildItem -LiteralPath $output -Directory |
                Sort-Object Name -Descending | Select-Object -First 1
        }
        if ($run -and (Test-Path -LiteralPath (Join-Path $run.FullName 'broker-ipc\broker-ready'))) {
            break
        }
        Start-Sleep -Milliseconds 30
    }
    if (-not $run -or -not (Test-Path -LiteralPath (Join-Path $run.FullName 'broker-ipc\broker-ready'))) {
        throw 'Broker did not become ready'
    }
    $brokers = @(Get-CimInstance Win32_Process -Filter "Name = 'Emumee.exe'" |
        Where-Object {
            $_.CommandLine -like '*_network_broker*' -and
            $_.CommandLine.Contains($run.FullName) -and
            $_.ExecutablePath -eq $exe
        })
    if ($brokers.Count -ne 1) {
        throw "Expected one exact broker process, found $($brokers.Count)"
    }
    Stop-Process -Id $brokers[0].ProcessId -Force
    Wait-Process -Id $cli.Id -Timeout 45
    $summary = Get-Content -LiteralPath (Join-Path $run.FullName 'summary.json') -Raw |
        ConvertFrom-Json
    $events = @(Get-Content -LiteralPath (Join-Path $run.FullName 'network-broker.json') -Raw |
        ConvertFrom-Json)
    if ($summary.status -ne 'failed' -or $summary.network_broker_complete -ne $false) {
        throw 'CLI did not flag incomplete broker log'
    }
    if (-not @($summary.errors | Where-Object { $_ -like '*journal*' -or $_ -like '*broker*' }).Count) {
        throw 'CLI did not report broker failure'
    }
    Write-Output "CLI broker crash: failed status, incomplete journal, $($events.Count) recovered events"
} finally {
    if (Get-Process -Id $cli.Id -ErrorAction SilentlyContinue) {
        Stop-Process -Id $cli.Id -Force
    }
}
