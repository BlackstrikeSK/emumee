Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$installations = @(& $vswhere -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
if (-not $installations) { throw 'MSVC C++ build tools are required' }
$msvcTools = Get-ChildItem -LiteralPath (Join-Path $installations[0] 'VC\Tools\MSVC') -Directory |
    Sort-Object Name -Descending | Select-Object -First 1
$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
$sdkVersion = Get-ChildItem -LiteralPath (Join-Path $sdkRoot 'Include') -Directory |
    Where-Object Name -Match '^10\.0\.\d+\.0$' |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $msvcTools -or -not $sdkVersion) { throw 'MSVC or Windows SDK headers are missing' }

$output = Join-Path $repoRoot 'output\guest-nslookup-toolchain'
$package = Join-Path $repoRoot 'src\emumee\guest_native'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$source = Join-Path $package 'nslookup_query.c'
foreach ($arch in @('x86', 'x64')) {
    $compiler = Join-Path $msvcTools.FullName ("bin\Hostx64\$arch\cl.exe")
    $target = Join-Path $output ("nslookup_query_$arch.exe")
    $object = Join-Path $output ("nslookup_query_$arch.obj")
    $imageBase = if ($arch -eq 'x64') { '0x190000000' } else { '0x600000' }
    $clArgs = @(
        '/nologo', '/O2', '/GS-', '/Zl', '/W4', '/TC',
        "/I$($msvcTools.FullName)\include",
        "/I$sdkRoot\Include\$($sdkVersion.Name)\um",
        "/I$sdkRoot\Include\$($sdkVersion.Name)\shared",
        "/I$sdkRoot\Include\$($sdkVersion.Name)\ucrt",
        "/Fo:$object", "/Fe:$target", $source,
        '/link', '/NODEFAULTLIB', '/ENTRY:entry', '/SUBSYSTEM:CONSOLE',
        "/BASE:$imageBase", '/DYNAMICBASE:NO',
        "/LIBPATH:$sdkRoot\Lib\$($sdkVersion.Name)\um\$arch",
        'kernel32.lib', 'iphlpapi.lib', 'dnsapi.lib'
    )
    & $compiler @clArgs
    if ($LASTEXITCODE -ne 0) { throw "Guest nslookup_query $arch compilation failed" }
    Copy-Item -LiteralPath $target -Destination (Join-Path $package ("nslookup_query_$arch.exe")) -Force
}
