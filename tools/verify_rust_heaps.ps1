param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$exe=Join-Path ([IO.Path]::GetFullPath((Join-Path $repo $Bundle))) 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){throw 'Preserve existing heap evidence.'}
$null=New-Item -ItemType Directory -Path $root
$cases=@(
 @{name='heap-lifecycle';live=0;heaps=1},@{name='heap-resize';live=0;heaps=1},
 @{name='heap-move';live=0;heaps=1},@{name='heap-in-place';live=0;heaps=1},
 @{name='heap-executable';live=0;heaps=1},@{name='heap-zero';live=0;heaps=1},
 @{name='heap-nx';error='*FETCH_PROT*';live=1;heaps=1},
 @{name='heap-freed';error='*READ_UNMAPPED*';live=0;heaps=1},
 @{name='heap-wrong-owner';error='*wrong-heap*';live=1;heaps=3},
 @{name='heap-double-free';error='*freed*';live=0;heaps=1},
 @{name='heap-virtual-free';error='*heap-owned*';live=1;heaps=1},
 @{name='heap-flags';error='*flags*';live=0;heaps=1},
 @{name='heap-fixed';error='*fixed arenas*';live=0;heaps=1}
)
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $run=Join-Path $root ($arch+'-'+$case.name)
 & $exe fixture --kind $case.name --arch $arch --max-instructions 10000 --isolated-output $run *> ($run+'.console.log')
 $exit=$LASTEXITCODE
 $result=Get-Content -LiteralPath (Join-Path $run 'fixture-result.json') -Raw | ConvertFrom-Json
 $e=$result.execution
 if($case.error){if($exit -eq 0 -or $e.completion_reason -ne 'error' -or $e.error -notlike $case.error -or $null -ne $e.guest_entry_return){throw "Heap failure mismatch $arch $($case.name): $($e.error)"}}
 elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Heap guest byte checks failed $arch $($case.name): $($e.error)"}
 if($e.architecture -ne $arch -or $null -eq $e.user_heaps -or @($e.user_heaps.blocks.PSObject.Properties).Count -ne $case.live -or @($e.user_heaps.heaps.PSObject.Properties).Count -ne $case.heaps){throw "Heap lifecycle report mismatch $arch $($case.name)"}
 if($e.network.calls -ne 0 -or $e.artifacts.Count -ne 0){throw 'Guest heaps exposed a host/network artifact.'}
 if($case.name -eq 'heap-in-place'){
  $failed=@($e.api_events | Where-Object {$_.api -like '*HeapReAlloc' -and $_.result -eq 0 -and $_.last_error -eq 77})
  if($failed.Count -ne 1){throw 'Failed in-place growth changed last error or fabricated success.'}
 }
 $records+=@{arch=$arch;case=$case.name;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;live_blocks=$case.live;verified=$true}
}}
$records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
Write-Output "Verified $($records.Count) contained guest heap ABI/byte/ownership/protection controls."
$global:LASTEXITCODE=0
