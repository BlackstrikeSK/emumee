param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$Resume)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'assert_rust_default_kernel_metadata.ps1')
$bundlePath=[IO.Path]::GetFullPath((Join-Path $repo $Bundle));$exe=Join-Path $bundlePath 'emumee-rs.exe'
$root=[IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
if(Test-Path -LiteralPath $root){if(-not $Resume){throw 'Preserve existing thread evidence; choose fresh root or explicit Resume.'}}else{$null=New-Item -ItemType Directory -Path $root}
$receipt=Get-Content -LiteralPath (Join-Path $bundlePath 'rust-worker-build.json') -Raw|ConvertFrom-Json
$cases=@(@{name='read'},@{name='ci-read'},@{name='execute';error='FETCH_PROT';symbol='cng.sys!BCryptVerifySignature'},@{name='write';error='WRITE_PROT';symbol='cng.sys!BCryptVerifySignature'},@{name='api-write';error='Metadata-only provider cng.sys!BCryptVerifySignature refuses write';api=$true},@{name='header-execute';error='FETCH_PROT';symbol='cng.sys!<image-metadata>'},@{name='header-api-write';error='Metadata-only provider cng.sys!<image-metadata> refuses write';api=$true},@{name='ci-execute';error='FETCH_PROT';symbol='ci.dll!CiCheckSignedFile'})
$records=@()
foreach($arch in @('x86','x64')){foreach($case in $cases){
 $kind='kernel-metadata-'+$case.name;$negative=[bool]$case.error;$calls=if($case.api){1}else{0};$modes=@('full');if(-not $negative){$modes+='before-return'}
 foreach($mode in $modes){
  $partial=$mode -eq 'before-return'
  if($partial){$baseline=@($records|Where-Object {$_.arch -eq $arch -and $_.kind -eq $kind -and -not $_.partial});if($baseline.Count -ne 1){throw 'Missing kernel-wait budget baseline.'};$budget=$baseline[0].instructions-1}else{$budget=10000}
  $run=Join-Path $root ($arch+'-'+$kind+$(if($partial){'-partial'}else{''}));$reused=Test-Path -LiteralPath $run
  if($reused){if(-not $Resume){throw 'Never overwrite an existing generated thread run.'}}
  else{& $exe fixture --kind $kind --arch $arch --max-instructions $budget --isolated-output $run *> ($run+'.console.log');$exit=$LASTEXITCODE}
  $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw|ConvertFrom-Json
  $requestPath=Join-Path $run 'request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
  $requestHash=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $resultPath=Join-Path $run 'fixture-result.json';$resultHash=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $workerExit=Get-Content -LiteralPath (Join-Path $run 'worker-exit.json') -Raw|ConvertFrom-Json
  $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
  foreach($key in @('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')){if($manifest.$key -cne $receipt.$key){throw 'Thread run belongs to another frozen build.'}}
  if($manifest.cleanup -ne 'restored' -or $workerExit.cleanup -ne 'restored' -or $workerExit.exit_code -ne 0 -or $manifest.request_sha256 -cne $requestHash -or $manifest.result_sha256 -cne $resultHash -or $result.request_sha256 -cne $requestHash -or $request.kind -ne $kind -or $request.architecture -ne $arch -or $request.max_instructions -ne $budget){throw 'Thread request/result/build/cleanup binding failed.'}
  $e=$result.execution
  if($reused){$exit=if($e.completion_reason -eq 'entry_return'){0}else{1}}
  if(-not $result.containment.app_container -or -not $result.containment.job_object -or -not $result.containment.child_process_blocked -or $result.containment.network_capabilities -ne 0){throw 'Metadata provider packaged containment failure.'}
  if($e.backend -ne 'rust/unicorn-x86' -or $e.architecture -ne $arch -or $null -eq $e.kernel_cpu -or $e.api_calls -ne $calls -or $e.api_events_omitted -ne 0 -or $e.network.calls -ne 0 -or @($e.artifacts).Count -ne 0 -or @($e.synthetic_providers).Count -ne 10 -or @($e.loaded_modules).Count -ne 11){throw 'Metadata provider actual kernel/import/API/module evidence mismatch.'}
  Assert-RustDefaultKernelMetadata -Execution $e -Architecture $arch
  foreach($profile in @(@{module='cng.sys';path='C:\Windows\system32\drivers\cng.sys';count=69;first=1;digest='3f0d2df8dec0ca5d42da691013e5e7ca8288f3bd361714fa9643e354040a2d29'},@{module='ci.dll';path='C:\Windows\system32\ci.dll';count=10;first=4;digest='8416c5cf965100293ea3c2edaadddd6af2a47c0c6f89c7723e740b18ffec12c0'})){
   $p=@($e.synthetic_providers|Where-Object {$_.module -eq $profile.module});if($p.Count -ne 1){throw 'Finite metadata group omitted/duplicated provider.'};$m=$p[0].metadata_only
   if($null -eq $m -or $null -ne $p[0].reference_catalog -or $p[0].exports -ne $profile.count -or $m.module -cne $profile.module -or $m.guest_path -cne $profile.path -or $m.permissions -cne 'r--' -or $m.ordinal_base -ne $profile.first -or @($m.named_exports).Count -ne $profile.count -or $m.catalog_sha256 -cne $profile.digest -or $m.legacy_source_sha256 -cne '4f20fe9c08a7956f1673c585198c8658cb8e9404e896c8d0f75508610b398814' -or $m.generated_image_sha256 -notmatch '^[0-9a-f]{64}$' -or $m.timestamp -ne 0 -or $m.checksum -ne 0 -or $m.entry_rva -ne 0){throw 'Metadata provider path/count/ordinal/hash/READ-NX/zero-header profile changed.'}
   $digestText='';for($i=0;$i -lt $profile.count;$i++){$item=$m.named_exports[$i];if($item.ordinal -ne $profile.first+$i -or $item.rva -ne 0x1000+$i*16){throw 'Metadata provider invented/reordered ordinal slot.'};$digestText+=[string]$item.ordinal+' '+$item.name+"`n"}
   $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($digestText))).ToLowerInvariant();if($digest -cne $profile.digest){throw 'Actual emitted metadata names/order differ from pinned AST digest.'}
  }
  if(@($e.api_events|Where-Object {$_.api -like 'cng*' -or $_.api -like 'ci.*'}).Count){throw 'Metadata-only provider fabricated crypto/function dispatch.'}
  if($negative){if($exit -ne 1 -or $e.completion_reason -ne 'error' -or $null -ne $e.guest_entry_return -or $e.error -notmatch [regex]::Escape($case.error)){throw 'Metadata provider write/fetch/API refusal was lost.'};if($case.symbol -and @($e.provider_denials|Where-Object {$_.name -ceq $case.symbol -and $_.kind -ceq 'metadata-only'}).Count -eq 0){throw 'Metadata denial lost exact module/symbol identity.'}}
  elseif($partial){if($exit -ne 1 -or $e.completion_reason -ne 'instruction_budget' -or $e.instruction_count -ne $budget -or $null -ne $e.guest_entry_return -or $null -ne $e.error){throw 'Metadata read prefix fabricated entry completion.'}}
  elseif($exit -ne 0 -or $e.completion_reason -ne 'entry_return' -or $e.guest_entry_return -ne 1 -or $null -ne $e.error){throw "Actual guest metadata address/header/machine/ordinal/read checks failed $arch $kind $($e.error)"}
  $records+=@{arch=$arch;kind=$kind;partial=$partial;instructions=$e.instruction_count;completion=$e.completion_reason;api_calls=$e.api_calls;reused=[bool]$reused;verified=$true}
  $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'verification.json') -Encoding utf8NoBOM
 }
}}
if($records.Count -ne 20){throw 'Metadata provider control count mismatch.'}
Write-Output "Verified $($records.Count) contained CNG/CI metadata-only address, read, ordinal/path/hash, fetch/write/API refusal and budget controls."
$global:LASTEXITCODE=0
