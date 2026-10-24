param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle))
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Use a fresh managed execution verification root.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
    @{kind='managed-rva-decode';value=82;instructions=75;return_kind='i32';fields=1;artifact_count=1;artifact_data=@('RUST');guest_files=1;array_objects=1;array_reads=5;array_writes=4;initializations=1;initialization_bytes=4;framework_calls=2},
    @{kind='managed-rva-decode';name='managed-rva-decode-before-ret';before_ret=$true;fields=1;artifact_count=1;artifact_data=@('RUST');guest_files=1},
    @{kind='managed-rva-decode';name='managed-rva-decode-before-write';budget=70;fields=1;artifact_count=0;guest_files=0;initializations=1;initialization_bytes=4},
    @{kind='managed-rva-bytes';value=82;instructions=8;return_kind='i32';fields=1;array_objects=1;initializations=1;initialization_bytes=4;framework_calls=1},
    @{kind='managed-rva-bytes';name='managed-rva-bytes-before-ret';before_ret=$true;fields=1},
    @{kind='managed-rva-i32';value=17;instructions=8;return_kind='i32';fields=1;array_objects=1;initializations=1;initialization_bytes=8;framework_calls=1},
    @{kind='managed-rva-i32';name='managed-rva-i32-before-ret';before_ret=$true;fields=1},
    @{kind='managed-rva-zero';value=0;instructions=8;return_kind='i32';fields=1;array_objects=1;initializations=1;initialization_bytes=0;framework_calls=1},
    @{kind='managed-rva-zero';name='managed-rva-zero-before-ret';before_ret=$true;fields=1},
    @{kind='managed-rva-twice';value=82;instructions=15;return_kind='i32';fields=1;array_objects=1;initializations=2;initialization_bytes=8;array_writes=1;framework_calls=2},
    @{kind='managed-rva-twice';name='managed-rva-twice-before-ret';before_ret=$true;fields=1},
    @{kind='managed-rva-bad-handle';error='argument type mismatch';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-missing-field';error='row index';instructions=4;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-no-rva';error='static non-literal RVA field';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-missing-row';error='no FieldRVA row';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-no-layout';error='no ClassLayout';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-bad-packing';error='packing';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-too-small';error='declared field storage';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-bad-rva';error='non-file-backed';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-reference-field';error='signature type';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-literal';error='static non-literal RVA field';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-wrong-array';error='byte/int32 vectors';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-null-array';error='ArgumentNullException: array';instructions=3;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-bad-signature';error='method/signature';instructions=5;fields=1;initializations=0;array_writes=0},
    @{kind='managed-rva-handle-branch';error='cannot be branch conditions';instructions=2;fields=1;initializations=0;array_writes=0},
    @{kind='managed-file-round-trip';value=82;instructions=38;return_kind='i32';artifact_count=1;artifact_data=@('RUST');guest_files=1;array_objects=3;framework_calls=3},
    @{kind='managed-file-round-trip';name='managed-file-round-trip-before-ret';before_ret=$true;artifact_count=1;artifact_data=@('RUST');guest_files=1},
    @{kind='managed-file-round-trip';name='managed-file-round-trip-before-write';budget=21;artifact_count=0;guest_files=0},
    @{kind='managed-file-overwrite';value=1;instructions=37;return_kind='i32';artifact_count=2;artifact_data=@('RUST','A');guest_files=1;framework_calls=3},
    @{kind='managed-file-overwrite';name='managed-file-overwrite-before-ret';before_ret=$true;artifact_count=2;artifact_data=@('RUST','A');guest_files=1},
    @{kind='managed-file-empty';value=0;instructions=11;return_kind='i32';artifact_count=0;guest_files=1;empty_files=1;framework_calls=2},
    @{kind='managed-file-empty';name='managed-file-empty-before-ret';before_ret=$true;artifact_count=0;guest_files=1;empty_files=1},
    @{kind='managed-file-empty-exists';value=1;instructions=9;return_kind='i32';artifact_count=0;guest_files=1;empty_files=1;framework_calls=2},
    @{kind='managed-file-empty-exists';name='managed-file-empty-exists-before-ret';before_ret=$true;artifact_count=0;guest_files=1;empty_files=1},
    @{kind='managed-file-exists';value=0;instructions=3;return_kind='i32';guest_files=0;framework_calls=1},
    @{kind='managed-file-exists';name='managed-file-exists-before-ret';before_ret=$true},
    @{kind='managed-file-exists-null';value=0;instructions=3;return_kind='i32';guest_files=0;framework_calls=1},
    @{kind='managed-file-exists-null';name='managed-file-exists-null-before-ret';before_ret=$true},
    @{kind='managed-file-escape';value=1;instructions=25;return_kind='i32';artifact_count=1;artifact_data=@('RUST');guest_files=1;framework_calls=2;escaped=$true},
    @{kind='managed-file-escape';name='managed-file-escape-before-ret';before_ret=$true;artifact_count=1;artifact_data=@('RUST');guest_files=1;escaped=$true},
    @{kind='managed-file-dedupe';value=2;instructions=31;return_kind='i32';artifact_count=1;artifact_data=@('RUST');guest_files=2;framework_calls=4;observations=4},
    @{kind='managed-file-dedupe';name='managed-file-dedupe-before-ret';before_ret=$true;artifact_count=1;artifact_data=@('RUST');guest_files=2;observations=4},
    @{kind='managed-file-missing';error='FileNotFoundException';instructions=2;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-parent-missing';error='DirectoryNotFoundException';instructions=22;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-null-path';error='ArgumentNullException: path';instructions=22;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-null-bytes';error='ArgumentNullException: bytes';instructions=3;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-invalid-path';error='ArgumentException: path';instructions=22;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-unsupported-path';error='Unmodeled managed file behavior';instructions=22;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-bad-signature';error='method/signature';instructions=22;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-bad-assembly';error='assembly/type';instructions=22;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-bad-array-type';error='argument type mismatch';instructions=22;guest_files=0;framework_calls=0;framework_attempts=1},
    @{kind='managed-file-partial';error='method/signature';instructions=23;artifact_count=1;artifact_data=@('RUST');guest_files=1;framework_calls=1;framework_attempts=2},
    @{kind='managed-array-byte';value=255;instructions=9;return_kind='i32';array_objects=1;array_reads=1;array_writes=1},
    @{kind='managed-array-byte';name='managed-array-byte-before-ret';before_ret=$true},
    @{kind='managed-array-i32';value=-17;guest=4294967279;instructions=9;return_kind='i32';array_objects=1;array_reads=1;array_writes=1},
    @{kind='managed-array-i32';name='managed-array-i32-before-ret';before_ret=$true},
    @{kind='managed-array-string';value=1;instructions=11;return_kind='i32';array_objects=1;array_reads=1;array_writes=1;objects=1},
    @{kind='managed-array-string';name='managed-array-string-before-ret';before_ret=$true},
    @{kind='managed-array-string-zero';value=1;instructions=7;return_kind='i32';array_objects=1;array_reads=1;array_writes=0;objects=0},
    @{kind='managed-array-string-zero';name='managed-array-string-zero-before-ret';before_ret=$true},
    @{kind='managed-array-length';value=3;instructions=5;return_kind='i32';array_objects=1;array_reads=0;array_writes=0},
    @{kind='managed-array-length';name='managed-array-length-before-ret';before_ret=$true},
    @{kind='managed-array-native-length';value=3;instructions=9;return_kind='i32';array_objects=2;array_reads=0;array_writes=0},
    @{kind='managed-array-native-length';name='managed-array-native-length-before-ret';before_ret=$true},
    @{kind='managed-array-local';value=17;instructions=11;return_kind='i32';array_objects=1;array_reads=1;array_writes=1},
    @{kind='managed-array-local';name='managed-array-local-before-ret';before_ret=$true},
    @{kind='managed-array-local-null';value=1;instructions=4;return_kind='i32';array_objects=0;array_reads=0;array_writes=0},
    @{kind='managed-array-local-null';name='managed-array-local-null-before-ret';before_ret=$true},
    @{kind='managed-array-call';value=17;instructions=12;return_kind='i32';array_objects=1;array_reads=1;array_writes=1;methods=2;calls=1;depth=2},
    @{kind='managed-array-call';name='managed-array-call-before-ret';before_ret=$true;methods=2},
    @{kind='managed-array-identity';value=1;instructions=5;return_kind='i32';array_objects=1;array_reads=0;array_writes=0},
    @{kind='managed-array-identity';name='managed-array-identity-before-ret';before_ret=$true},
    @{kind='managed-array-different';value=0;instructions=6;return_kind='i32';array_objects=2;array_reads=0;array_writes=0},
    @{kind='managed-array-different';name='managed-array-different-before-ret';before_ret=$true},
    @{kind='managed-array-zero-byte';value=0;instructions=5;return_kind='i32';array_objects=1;array_reads=1;array_writes=0},
    @{kind='managed-array-zero-byte';name='managed-array-zero-byte-before-ret';before_ret=$true},
    @{kind='managed-array-vs-string';value=0;instructions=5;return_kind='i32';array_objects=1;array_reads=0;array_writes=0;objects=1},
    @{kind='managed-array-vs-string';name='managed-array-vs-string-before-ret';before_ret=$true},
    @{kind='managed-array-length-type';error='return type';instructions=4;array_objects=1;array_writes=0},
    @{kind='managed-array-null';error='NullReferenceException';instructions=3;array_objects=0;array_writes=0},
    @{kind='managed-array-bounds';error='IndexOutOfRangeException';instructions=6;array_objects=1;array_writes=0},
    @{kind='managed-array-bad-value';error='store value type';instructions=6;array_objects=1;array_writes=0},
    @{kind='managed-array-bad-opcode';error='opcode/type';instructions=4;array_objects=1;array_writes=0},
    @{kind='managed-array-too-large';error='element limit';instructions=2;array_objects=0;array_writes=0},
    @{kind='managed-array-negative';error='OverflowException';instructions=2;array_objects=0;array_writes=0},
    @{kind='managed-array-unknown-type';error='Unmodeled array element type';instructions=2;array_objects=0;array_writes=0},
    @{kind='managed-array-bad-assembly';error='array element assembly/type';instructions=2;array_objects=0;array_writes=0},
    @{kind='managed-array-bad-local';error='local store type';instructions=3;array_objects=1;array_writes=0},
    @{kind='managed-array-bad-length-type';error='int32 or native-int';instructions=2;array_objects=0;array_writes=0},
    @{kind='managed-array-quota';error='array object limit';budget=20000;instructions=16386;array_objects=4096;array_writes=0},
    @{kind='managed-array-quota';name='managed-array-quota-before-limit';budget=4000;array_objects=1000;array_writes=0},
    @{kind='managed-framework-strings';value=3;instructions=7;return_kind='i32';objects=3;framework_calls=3;console="Hi!`r`n"},
    @{kind='managed-framework-strings';name='managed-framework-strings-before-ret';before_ret=$true},
    @{kind='managed-framework-concat-identity';value=0;instructions=6;return_kind='i32';objects=4;framework_calls=1},
    @{kind='managed-framework-concat-identity';name='managed-framework-concat-identity-before-ret';before_ret=$true},
    @{kind='managed-framework-string-equality';value=1;instructions=6;return_kind='i32';objects=4;framework_calls=2},
    @{kind='managed-framework-string-equality';name='managed-framework-string-equality-before-ret';before_ret=$true},
    @{kind='managed-framework-concat-empty';value=1;instructions=6;return_kind='i32';objects=1;framework_calls=1},
    @{kind='managed-framework-concat-empty';name='managed-framework-concat-empty-before-ret';before_ret=$true},
    @{kind='managed-framework-concat-null';value=0;instructions=5;return_kind='i32';objects=1;framework_calls=2},
    @{kind='managed-framework-concat-null';name='managed-framework-concat-null-before-ret';before_ret=$true},
    @{kind='managed-framework-unicode-length';value=4;instructions=3;return_kind='i32';objects=1;framework_calls=1},
    @{kind='managed-framework-unicode-length';name='managed-framework-unicode-length-before-ret';before_ret=$true},
    @{kind='managed-framework-char';value=55296;instructions=4;return_kind='i32';objects=1;framework_calls=1},
    @{kind='managed-framework-char';name='managed-framework-char-before-ret';before_ret=$true},
    @{kind='managed-framework-console';value=17;instructions=7;return_kind='i32';objects=1;framework_calls=4;console="-17`r`n`r`n"},
    @{kind='managed-framework-console';name='managed-framework-console-before-ret';before_ret=$true},
    @{kind='managed-framework-console-null';value=17;instructions=4;return_kind='i32';objects=0;framework_calls=1;console="`r`n"},
    @{kind='managed-framework-console-null';name='managed-framework-console-null-before-ret';before_ret=$true},
    @{kind='managed-framework-console-types';value=17;instructions=10;return_kind='i32';objects=0;framework_calls=4;console_units=25;surrogate=$true},
    @{kind='managed-framework-console-types';name='managed-framework-console-types-before-ret';before_ret=$true},
    @{kind='managed-framework-null-or-empty';value=1;instructions=5;return_kind='i32';objects=1;framework_calls=2},
    @{kind='managed-framework-null-or-empty';name='managed-framework-null-or-empty-before-ret';before_ret=$true},
    @{kind='managed-framework-inequality';value=1;instructions=4;return_kind='i32';objects=1;framework_calls=1},
    @{kind='managed-framework-inequality';name='managed-framework-inequality-before-ret';before_ret=$true},
    @{kind='managed-framework-null-length';error='NullReferenceException';instructions=2;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-bad-index';error='IndexOutOfRangeException';instructions=3;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-bad-assembly';error='assembly/type';instructions=2;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-bad-signature';error='method/signature';instructions=2;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-static-virtual';error='static framework method';instructions=3;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-unknown';error='method/signature';instructions=1;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-bad-owner';error='MemberRef owner';instructions=2;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-bad-scope';error='AssemblyRef';instructions=2;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-argument-type';error='argument type mismatch';instructions=2;framework_calls=0;framework_attempts=1},
    @{kind='managed-framework-console-limit';error='console output limit';instructions=98306;budget=200000;framework_calls=32768;framework_attempts=32769;console_units=65536},
    @{kind='managed-framework-console-limit';name='managed-framework-events-bound';budget=600;framework_calls=200;framework_attempts=200;console_units=400},
    @{kind='managed-string-identity';value=1;instructions=4;return_kind='i32';objects=1},
    @{kind='managed-string-identity';name='managed-string-identity-before-ret';before_ret=$true},
    @{kind='managed-string-aliases';value=1;instructions=4;return_kind='i32';objects=1},
    @{kind='managed-string-aliases';name='managed-string-aliases-before-ret';before_ret=$true},
    @{kind='managed-string-local';value=1;instructions=6;return_kind='i32';objects=1},
    @{kind='managed-string-local';name='managed-string-local-before-ret';before_ret=$true},
    @{kind='managed-string-local-null';value=1;instructions=4;return_kind='i32';objects=0},
    @{kind='managed-string-call';value=1;instructions=7;return_kind='i32';objects=1;methods=2;calls=1;depth=2},
    @{kind='managed-string-call';name='managed-string-call-before-ret';before_ret=$true;methods=2},
    @{kind='managed-string-return';reference=1;instructions=2;return_kind='string_ref';objects=1},
    @{kind='managed-string-return';name='managed-string-return-before-ret';before_ret=$true},
    @{kind='managed-string-bad-token';error='#US token';instructions=1;objects=0},
    @{kind='managed-string-missing';error='compressed integer';instructions=1;objects=0},
    @{kind='managed-string-bad-type';error='local store type mismatch';instructions=2;objects=0},
    @{kind='managed-string-relational';error='comparison operand types';instructions=3;objects=1},
    @{kind='managed-locals-loop';value=17;instructions=176;return_kind='i32';calls=0;depth=1},
    @{kind='managed-locals-loop';name='managed-locals-loop-before-ret';before_ret=$true},
    @{kind='managed-local-zero';value=0;instructions=2;return_kind='i32'},
    @{kind='managed-local-zero';name='managed-local-zero-before-ret';before_ret=$true},
    @{kind='managed-local-indexed';value=17;instructions=6;return_kind='i32'},
    @{kind='managed-local-indexed';name='managed-local-indexed-before-ret';before_ret=$true},
    @{kind='managed-call-arguments';value=10;instructions=8;return_kind='i32';methods=2;calls=1;depth=2},
    @{kind='managed-call-arguments';name='managed-call-arguments-before-ret';before_ret=$true;methods=2},
    @{kind='managed-argument-store';value=18;instructions=9;return_kind='i32';methods=2;calls=1;depth=2},
    @{kind='managed-argument-store';name='managed-argument-store-before-ret';before_ret=$true;methods=2},
    @{kind='managed-void-return';void=$true;instructions=1;calls=0;depth=1},
    @{kind='managed-void-call';value=17;instructions=4;return_kind='i32';methods=2;calls=1;depth=2},
    @{kind='managed-void-call';name='managed-void-call-before-ret';before_ret=$true;methods=2},
    @{kind='managed-recursive';value=17;instructions=126;return_kind='i32';methods=2;calls=18;depth=19},
    @{kind='managed-recursive';name='managed-recursive-before-ret';before_ret=$true;methods=2},
    @{kind='managed-deep-recursion';error='call depth exceeds 64';instructions=380;methods=2;calls=63;depth=64},
    @{kind='managed-local-uninitialized';error='Uninitialized managed local';instructions=1},
    @{kind='managed-local-bad-type';error='local store type mismatch';instructions=2},
    @{kind='managed-argument-bad-type';error='argument type mismatch';instructions=3;methods=2;calls=0;depth=1},
    @{kind='managed-return';value=17;instructions=2;return_kind='i32'},
    @{kind='managed-return';name='managed-return-before-ret';before_ret=$true},
    @{kind='managed-loop';value=17;instructions=72;return_kind='i32'},
    @{kind='managed-loop';name='managed-loop-before-ret';before_ret=$true},
    @{kind='managed-arithmetic';value=[int]::MaxValue;instructions=6;return_kind='i32'},
    @{kind='managed-arithmetic';name='managed-arithmetic-before-ret';before_ret=$true},
    @{kind='managed-i64-arithmetic';value=[long]::MaxValue;instructions=8;return_kind='i64'},
    @{kind='managed-i64-arithmetic';name='managed-i64-arithmetic-before-ret';before_ret=$true},
    @{kind='managed-bad-branch';error='inside an operand';instructions=1},
    @{kind='managed-underflow';error='underflow';instructions=1},
    @{kind='managed-divide-zero';error='division';instructions=3},
    @{kind='managed-unsupported';error='Unmodeled CIL instruction';instructions=2},
    @{kind='managed-return-stack';error='extra evaluation stack';instructions=3},
    @{kind='managed-stack-limit';error='max_stack';instructions=9},
    @{kind='managed-infinite';budget=37}
)
$records=@()
foreach($arch in @('x86','x64')) {
    foreach($case in $cases) {
        $name=if($case.name){$case.name}else{$case.kind}
        $budget=if($case.before_ret) {
            $baseline=@($records | Where-Object {$_.arch -eq $arch -and $_.kind -eq $case.kind -and $_.completion -eq 'entry_return'})
            if($baseline.Count -ne 1){throw 'Missing managed return baseline.'}
            $baseline[0].instructions-1
        } elseif($case.budget){$case.budget}else{1000}
        $run=Join-Path $root ($arch+'-'+$name)
        & (Join-Path $bundlePath 'emumee-rs.exe') fixture --arch $arch --kind $case.kind --iterations 17 --max-instructions $budget --isolated-output $run *> ($run+'.console.log')
        $exit=$LASTEXITCODE
        $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw | ConvertFrom-Json
        $execution=$result.execution
        if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Managed worker containment failure.'}
        $methods=if($case.methods){$case.methods}else{1}
        $artifactCount=if($case.ContainsKey('artifact_count')){$case.artifact_count}else{0}
        if($execution.backend -ne 'rust/managed-il' -or $execution.architecture -ne $arch -or $execution.metadata.methods -ne $methods -or $execution.artifacts.Count -ne $artifactCount -or $execution.scope -notlike '*No host CLR*'){throw 'Managed request fell through to another backend or lost metadata/artifacts.'}
        if($case.ContainsKey('fields') -and $execution.metadata.fields -ne $case.fields){throw 'Managed field metadata count differs.'}
        if($case.ContainsKey('guest_files') -and $execution.framework.files.files -ne $case.guest_files){throw 'Managed guest file count differs.'}
        if($case.ContainsKey('empty_files') -and $execution.framework.files.empty_files -ne $case.empty_files){throw 'Managed empty file state differs.'}
        foreach($payload in $case.artifact_data) {
            $expectedBytes=[Text.Encoding]::ASCII.GetBytes($payload)
            $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expectedBytes)).ToLowerInvariant()
            $found=@($execution.artifacts | Where-Object {$_.sha256 -eq $digest})
            if($found.Count -ne 1 -or $found[0].filename -cne ($digest+'.bin') -or $found[0].size -ne $expectedBytes.Length){throw 'Managed artifact metadata differs from actual guest bytes.'}
            $diskBytes=[IO.File]::ReadAllBytes((Join-Path $run ('artifacts\'+$digest+'.bin')))
            if([Convert]::ToHexString($diskBytes) -cne [Convert]::ToHexString($expectedBytes)){throw 'Managed worker artifact payload differs.'}
            if($case.observations -and $found[0].observations.Count -ne $case.observations){throw 'Managed artifact dedup lost provenance.'}
            foreach($observation in $found[0].observations) {
                if($observation.kind -ne 'guest_file' -or $observation.source -notin @('managed_write_all_bytes','managed_virtual_file_at_stop')){throw 'Managed capture has the wrong evidence kind/source.'}
                if($case.escaped -and $observation.guest_path -cne 'c:\escaped.bin'){throw 'Guest traversal path was not kept as virtual metadata.'}
            }
        }
        if($case.ContainsKey('calls') -and ($execution.managed_calls -ne $case.calls -or $execution.max_call_depth -ne $case.depth)){throw 'Managed frame/call evidence differs from actual dispatch.'}
        if($case.ContainsKey('objects') -and $execution.heap.string_objects -ne $case.objects){throw 'Managed interned string identity count differs.'}
        if($case.ContainsKey('array_objects') -and $execution.arrays.objects -ne $case.array_objects){throw 'Managed array object count differs.'}
        if($case.ContainsKey('array_reads') -and $execution.arrays.element_reads -ne $case.array_reads){throw 'Managed array read evidence differs.'}
        if($case.ContainsKey('array_writes') -and $execution.arrays.element_writes -ne $case.array_writes){throw 'Managed array write evidence differs.'}
        if($case.ContainsKey('initializations') -and $execution.arrays.initializations -ne $case.initializations){throw 'Managed array initializer count differs.'}
        if($case.ContainsKey('initialization_bytes') -and $execution.arrays.initialization_bytes -ne $case.initialization_bytes){throw 'Managed array initializer byte count differs.'}
        if($execution.arrays.evidence.Count -gt 64 -or $execution.arrays.storage_bytes -gt $execution.arrays.storage_limit -or $execution.arrays.objects -gt $execution.arrays.object_limit){throw 'Managed array bounds differ.'}
        foreach($arrayEvidence in $execution.arrays.evidence) { if($arrayEvidence.preview.Count -gt 32 -or $arrayEvidence.length -gt $execution.arrays.element_limit){throw 'Managed array preview/element bound differs.'} }
        if($case.ContainsKey('framework_calls') -and $execution.framework.completed_calls -ne $case.framework_calls){throw 'Framework completed-call evidence differs.'}
        if($case.ContainsKey('framework_attempts') -and $execution.framework.attempts -ne $case.framework_attempts){throw 'Framework attempt evidence differs.'}
        if($execution.framework.events.Count -gt 128 -or $execution.framework.events.Count+$execution.framework.omitted_events -ne $execution.framework.attempts){throw 'Framework event bound/accounting differs.'}
        $frameworkSum=($execution.framework.counts.PSObject.Properties.Value | Measure-Object -Sum).Sum
        if([long]$frameworkSum -ne $execution.framework.completed_calls -or $execution.framework.console_output.utf16.Count -gt $execution.framework.console_output.utf16_limit){throw 'Framework call/output accounting differs.'}
        if($case.ContainsKey('console') -and $execution.framework.console_output.text_lossy -cne $case.console){throw 'Guest console text or Windows line endings differ.'}
        if($case.ContainsKey('console_units') -and $execution.framework.console_output.utf16.Count -ne $case.console_units){throw 'Guest UTF16 console bound differs.'}
        if($case.surrogate -and ($execution.framework.console_output.utf16[-1] -ne 55296 -or [int]$execution.framework.console_output.text_lossy[-1] -ne 65533)){throw 'Console lost raw UTF16 or failed to label its lossy display.'}
        if($case.before_ret -or ($case.budget -and -not $case.error)) {
            if($exit -ne 1 -or $execution.completion_reason -ne 'instruction_budget' -or $execution.instruction_count -ne $budget -or $null -ne $execution.guest_entry_return -or $null -ne $execution.managed_return){throw 'Managed budget produced a fake or early return.'}
        } elseif($case.error) {
            if($exit -ne 1 -or $execution.completion_reason -ne 'error' -or $execution.error -notlike ('*'+$case.error+'*') -or $null -ne $execution.guest_entry_return){throw 'Managed negative control did not stop explicitly.'}
        } elseif($case.void) {
            if($exit -ne 0 -or $execution.completion_reason -ne 'entry_return' -or $null -ne $execution.guest_entry_return -or $null -ne $execution.managed_return -or $execution.entry_signature.return_type.kind -ne 'void'){throw 'Void method invented a value or failed to return.'}
        } elseif($case.reference) {
            if($exit -ne 0 -or $execution.completion_reason -ne 'entry_return' -or $null -ne $execution.guest_entry_return -or $execution.managed_return.kind -ne 'string_ref' -or $execution.managed_return.value -ne $case.reference){throw 'Managed string return lost its guest identity.'}
            if(($execution.heap.strings[0].utf16_preview -join ',') -ne '65,55296,0,56320' -or $execution.heap.strings[0].utf16_length -ne 4){throw 'Managed string storage lost UTF16 code units.'}
        } else {
            $expectedGuest=if($case.ContainsKey('guest')){$case.guest}else{$case.value}
            if($exit -ne 0 -or $execution.completion_reason -ne 'entry_return' -or $execution.guest_entry_return -ne $expectedGuest -or $execution.managed_return.value -ne $case.value -or $execution.managed_return.kind -ne $case.return_kind){throw 'Managed guest return differs from its actual IL.'}
        }
        if($case.instructions -and $execution.instruction_count -ne $case.instructions){throw 'Managed instruction accounting changed.'}
        $count=($execution.opcode_counts.PSObject.Properties.Value | Measure-Object -Sum).Sum
        if($count -ne $execution.instruction_count -or $execution.instruction_tail.Count -gt 128){throw 'Managed opcode/trace evidence is inconsistent.'}
        $records+=@{arch=$arch;kind=$case.kind;case=$name;completion=$execution.completion_reason;instructions=$execution.instruction_count;return=$execution.guest_entry_return;error=$execution.error;backend=$execution.backend}
    }
}
$records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) isolated managed IL execution controls."
