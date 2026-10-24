param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve prior journal qualification evidence.'}
$null=New-Item -ItemType Directory -Path $root
$utf8=[Text.UTF8Encoding]::new($false)
$attempt="{`"event`":`"http_request_attempt`",`"url`":`"https://example.invalid/`"}`n"
$close="{`"event`":`"broker_closed`"}`n"
$name64=([string][char]0xe9)*64
$cases=@(
    @{name='closed';data=$close;prefix=$close;events=1;closed=$true},
    @{name='attempt-closed';data=$attempt+$close;prefix=$attempt+$close;events=2;closed=$true},
    @{name='attempt-only';data=$attempt;prefix=$attempt;events=1;reason='missing_close_marker'},
    @{name='partial';data=$attempt+'{';prefix=$attempt;events=1;reason='partial_record'},
    @{name='partial-after-close';data=$close+'{';prefix=$close;events=1;reason='partial_record'},
    @{name='bad-json';data=$attempt+"{`n"+$close;prefix=$attempt;events=1;reason='malformed_json'},
    @{name='bad-utf8';bytes=($utf8.GetBytes($attempt)+[byte[]]@(255,10));prefix=$attempt;events=1;reason='malformed_json'},
    @{name='bad-event';data=$attempt+"[]`n"+$close;prefix=$attempt;events=1;reason='malformed_event'},
    @{name='integer-range';data=$attempt+"{`"event`":`"x`",`"value`":18446744073709551616}`n"+$close;prefix=$attempt;events=1;reason='integer_range'},
    @{name='empty';data='';prefix='';events=0;reason='missing_close_marker'},
    @{name='name-64';data="{`"event`":`"$name64`"}`n";prefix="{`"event`":`"$name64`"}`n";events=1;reason='missing_close_marker'},
    @{name='name-65';data="{`"event`":`"${name64}x`"}`n";prefix='';events=0;reason='malformed_event'},
    @{name='close-extra';data="{`"event`":`"broker_closed`",`"extra`":true}`n";prefix="{`"event`":`"broker_closed`",`"extra`":true}`n";events=1;reason='missing_close_marker'},
    @{name='close-not-last';data=$close+$attempt;prefix=$close+$attempt;events=2;reason='missing_close_marker'},
    @{name='blank-tail';data=$attempt+"`n"+$close;prefix=$attempt;events=1;reason='malformed_json'},
    @{name='crlf';data=$close.Replace("`n","`r`n");prefix=$close.Replace("`n","`r`n");events=1;closed=$true},
    @{name='record-size';data=$attempt+(' '*40960)+"`n"+$close;prefix=$attempt;events=1;reason='record_limit'},
    @{name='record-nodes';data=$attempt+'{"event":"x","data":['+('0,'*8192)+"0]}`n"+$close;prefix=$attempt;events=1;reason='node_limit'}
)
$records=@()
foreach($case in $cases) {
    $inputPath=Join-Path $root ($case.name+'.journal')
    [byte[]]$bytes=@(if($case.ContainsKey('bytes')){$case.bytes}else{$utf8.GetBytes($case.data)})
    [IO.File]::WriteAllBytes($inputPath,$bytes)
    $hash=(Get-FileHash -LiteralPath $inputPath).Hash.ToLowerInvariant()
    $resultPath=Join-Path $root ($case.name+'.json')
    & $exe inspect-broker-journal $inputPath > $resultPath 2> (Join-Path $root ($case.name+'.stderr.txt'))
    $exit=$LASTEXITCODE
    $result=Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    $prefix=$utf8.GetBytes($case.prefix)
    $prefixHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($prefix)).ToLowerInvariant()
    if($exit -ne [int](-not $case.closed) -or $result.closed -ne [bool]$case.closed -or $result.events.Count -ne $case.events -or $result.stop_reason -ne $case.reason -or $result.source_sha256 -ne $hash -or $result.valid_prefix_sha256 -ne $prefixHash -or $result.valid_bytes -ne $prefix.Length -or $result.unrecovered_bytes -ne ($bytes.Length-$prefix.Length) -or $result.source_bytes -ne $bytes.Length){throw "Journal recovery mismatch: $($case.name)"}
    if((Get-FileHash -LiteralPath $inputPath).Hash.ToLowerInvariant() -ne $hash){throw 'Journal inspection modified source evidence.'}
    if($case.name -eq 'attempt-closed' -and $result.events[0].event -ne 'http_request_attempt'){throw 'Recovered attempt was rewritten as a successful request.'}
    $records+=@{case=$case.name;exit=$exit;events=$result.events.Count;closed=$result.closed;stop_reason=$result.stop_reason;source_sha256=$hash;valid_bytes=$result.valid_bytes;verified=$true}
}
foreach($case in @('oversize','hardlink')) {
    $path=Join-Path $root ($case+'.journal')
    if($case -eq 'oversize') {
        $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew)
        try{$stream.SetLength(64*1024*1024+1)}finally{$stream.Dispose()}
    } else {
        $null=New-Item -ItemType HardLink -Path $path -Target (Join-Path $root 'closed.journal')
    }
    & $exe inspect-broker-journal $path *> (Join-Path $root ($case+'.refusal.txt'))
    if($LASTEXITCODE -ne 2 -or (Get-Content -LiteralPath (Join-Path $root ($case+'.refusal.txt')) -Raw) -notlike '*Worker file type, links or size rejected*'){throw "Journal bounded-read refusal failed: $case"}
    $records+=@{case=$case;exit=2;verified=$true}
}
$records | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) read-only broker journal controls. No network or broker process was started."
