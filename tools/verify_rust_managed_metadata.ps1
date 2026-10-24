param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve previous evidence; select a fresh output root.'}
$null=New-Item -ItemType Directory -Path $root
$exe=Join-Path $bundlePath 'emumee-rs.exe'
$records=@()
foreach($arch in @('x86','x64')) {
    $inputPath=Join-Path $root ($arch+'-managed-fixture.exe')
    $generation=Join-Path $root ($arch+'-generated.json')
    & $exe managed-fixture --arch $arch --write-input $inputPath *> $generation
    if($LASTEXITCODE -ne 0){throw 'Rust managed fixture generator failed.'}
    $generated=Get-Content -LiteralPath $generation -Raw | ConvertFrom-Json
    $inspection=Join-Path $root ($arch+'-inspection.json')
    & $exe inspect-managed $inputPath *> $inspection
    if($LASTEXITCODE -ne 0){throw 'Rust managed metadata inspection failed.'}
    $result=Get-Content -LiteralPath $inspection -Raw | ConvertFrom-Json
    if(-not $result.sample.managed -or $result.sample.architecture -ne $arch -or $result.sample.sha256 -ne $generated.sample.sha256 -or $result.managed.assembly_name -ne 'Fixture' -or $result.managed.methods -ne 1 -or $result.managed.type_definitions -ne 1 -or $result.managed.cli.entry_point -ne 0x06000001 -or $result.managed.streams.Count -ne 5 -or $result.managed.scope -notlike '*No host CLR*') {throw 'Managed metadata evidence does not match the generated fixture.'}
    $records+=@{arch=$arch;case='generated-and-inspected';sha256=$result.sample.sha256;methods=$result.managed.methods}
    $hash=(Get-FileHash -LiteralPath $inputPath).Hash
    & $exe managed-fixture --arch $arch --write-input $inputPath *> (Join-Path $root ($arch+'-existing-refusal.log'))
    if($LASTEXITCODE -ne 2 -or (Get-FileHash -LiteralPath $inputPath).Hash -ne $hash){throw 'Managed fixture generation overwrote an existing input.'}
    $records+=@{arch=$arch;case='existing-input-preserved'}
    $cases=@(
        @{name='signature';at=0x480;bytes=[byte[]]@(0);error='BSJB'},
        @{name='stream-overlap';at=0x4a0;bytes=[byte[]]@(0,0,0,0);error='overlap'},
        @{name='duplicate-stream';at=0x4d8;bytes=[Text.Encoding]::ASCII.GetBytes("#Blob`0");error='duplicate'},
        @{name='row-bound';at=0x504;bytes=[byte[]]@(255,255,255,255);error='row count'},
        @{name='metadata-bound';at=0x40c;bytes=[byte[]]@(1,0,0,4);error='64MiB'},
        @{name='entry-token';at=0x414;bytes=[byte[]]@(2,0,0,6);error='entry token'}
    )
    foreach($case in $cases) {
        $bytes=[IO.File]::ReadAllBytes($inputPath)
        [Array]::Copy($case.bytes,0,$bytes,$case.at,$case.bytes.Length)
        $malformed=Join-Path $root ($arch+'-'+$case.name+'.exe')
        [IO.File]::WriteAllBytes($malformed,$bytes)
        $log=Join-Path $root ($arch+'-'+$case.name+'.log')
        & $exe inspect-managed $malformed *> $log
        if($LASTEXITCODE -ne 2 -or (Get-Content -LiteralPath $log -Raw) -notlike ('*'+$case.error+'*')){throw ('Malformed managed control failed: '+$case.name)}
        $records+=@{arch=$arch;case=$case.name;rejected=$true}
    }
}
$records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) generated managed metadata controls; no host CLR execution."
