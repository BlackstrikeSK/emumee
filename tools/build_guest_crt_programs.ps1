Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Builds the harmless compiler-produced legacy CRT programs the M5 exit
# criterion requires, for x86 and x64. The import library is generated from a
# module definition so the programs bind the legacy msvcrt.dll exports the
# profile models instead of the host toolchain's own runtime.

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

$output = Join-Path $repoRoot 'output\guest-crt-toolchain'
$package = Join-Path $repoRoot 'src\emumee\guest_native'
New-Item -ItemType Directory -Path $output -Force | Out-Null

# Only exports this profile models are offered to the programs.
$exports = @(
    'malloc', 'calloc', 'free', 'memset', 'memcpy', 'memcmp',
    'strcpy', 'strncpy', 'strcat', 'strncat', 'strlen', 'strcmp', 'strncmp',
    'strchr', 'strrchr', 'strstr', 'strcspn', '_stricmp', '_strlwr', '_strupr',
    'sprintf', '_snprintf', 'sscanf', 'puts', 'fopen', 'fread', 'fclose',
    '__stdio_common_vsprintf', '__stdio_common_vfprintf', '__acrt_iob_func', '_errno',
    'fseek', 'ftell', 'fputc', 'fflush', '_fileno',
    'exit', '_exit', '_cexit', '_crt_atexit', '_onexit', 'atoi', 'abs',
    '_set_new_mode', '_controlfp', 'rand', 'srand', 'time', 'clock',
    '__p___argc', '__p___argv', '__p__acmdln', '__p__fmode', '_set_fmode',
    '__set_app_type', 'setlocale', '_itoa', '_ltoa', 'tolower', 'toupper'
)
$definition = Join-Path $output 'msvcrt.def'
$lines = @('LIBRARY msvcrt.dll', 'EXPORTS') + $exports
[System.IO.File]::WriteAllLines($definition, $lines)

foreach ($arch in @('x86', 'x64')) {
    $library = Join-Path $output ("msvcrt_$arch.lib")
    $machine = if ($arch -eq 'x64') { 'X64' } else { 'X86' }
    & (Join-Path $msvcTools.FullName "bin\Hostx64\$arch\lib.exe") '/nologo' "/MACHINE:$machine" `
        "/DEF:$definition" "/OUT:$library" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Legacy msvcrt import library ($arch) failed" }

    $imageBase = if ($arch -eq 'x64') { '0x180000000' } else { '0x600000' }
    foreach ($name in @('crt_program', 'crt_refusal')) {
        $compiler = Join-Path $msvcTools.FullName ("bin\Hostx64\$arch\cl.exe")
        $source = Join-Path $package ("$name.c")
        $target = Join-Path $output ("${name}_$arch.exe")
        $clArgs = @(
            '/nologo', '/O2', '/GS-', '/Zl', '/W4', '/WX', '/TC',
            '/D_CRT_SECURE_NO_WARNINGS',
            "/I$($msvcTools.FullName)\include",
            "/I$sdkRoot\Include\$($sdkVersion.Name)\um",
            "/I$sdkRoot\Include\$($sdkVersion.Name)\shared",
            "/I$sdkRoot\Include\$($sdkVersion.Name)\ucrt",
            "/Fo:$output\${name}_$arch.obj", "/Fe:$target", $source,
            '/link', '/NODEFAULTLIB', '/ENTRY:entry', '/SUBSYSTEM:CONSOLE',
            "/BASE:$imageBase", '/DYNAMICBASE:NO', '/FIXED', '/NXCOMPAT:NO',
            "/LIBPATH:$sdkRoot\Lib\$($sdkVersion.Name)\um\$arch",
            $library
        )
        & $compiler @clArgs
        if ($LASTEXITCODE -ne 0) { throw "Guest $name $arch compilation failed" }
        Copy-Item -LiteralPath $target -Destination (Join-Path $package ("${name}_$arch.exe")) -Force
    }
}
Write-Host "Guest CRT programs built in $package."
