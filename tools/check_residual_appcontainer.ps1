param(
    [string[]]$Roots = @('dist\Emumee', 'output')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$directoryCount = 0
$fileCount = 0
$explicitGrants = New-Object 'System.Collections.Generic.List[string]'
$privateJournals = New-Object 'System.Collections.Generic.List[string]'
foreach ($root in $Roots) {
    $resolved = [System.IO.Path]::GetFullPath((Join-Path $repo $root))
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "Missing scan root: $resolved"
    }
    $entries = @((Get-Item -LiteralPath $resolved)) +
               @(Get-ChildItem -LiteralPath $resolved -Recurse -Force)
    foreach ($entry in $entries) {
        if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Reparse point prevents a complete ACL scan: $($entry.FullName)"
        }
        if ($entry.PSIsContainer) { $directoryCount++ } else { $fileCount++ }
        foreach ($rule in (Get-Acl -LiteralPath $entry.FullName).Access) {
            if ($rule.IsInherited) { continue }
            $identity = $rule.IdentityReference.Value
            if ($identity -like 'S-1-15-2-*') {
                $explicitGrants.Add($entry.FullName)
                continue
            }
            try {
                $translated = $rule.IdentityReference.Translate(
                    [System.Security.Principal.SecurityIdentifier]).Value
                if ($translated -like 'S-1-15-2-*') { $explicitGrants.Add($entry.FullName) }
            } catch [System.Security.Principal.IdentityNotMappedException] {
                # Unknown identities remain visible by their raw SID above.
            }
        }
        if (-not $entry.PSIsContainer -and
            $entry.Name -match '^\.[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.network-broker\.journal$') {
            $privateJournals.Add($entry.FullName)
        }
    }
}
$bundleRoot = [System.IO.Path]::GetFullPath((Join-Path $repo 'dist\Emumee'))
$workers = @(Get-CimInstance Win32_Process -Filter "name = 'Emumee.exe'" |
    Where-Object {
        $_.ExecutablePath -and
        [System.IO.Path]::GetFullPath($_.ExecutablePath).StartsWith(
            $bundleRoot + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase)
    })
Write-Output "Scanned $directoryCount directories and $fileCount files; explicit AppContainer SID grants: $($explicitGrants.Count); private broker journals: $($privateJournals.Count); packaged Emumee processes: $($workers.Count)"
if ($explicitGrants.Count -gt 0) {
    $explicitGrants | Select-Object -First 20 | ForEach-Object { Write-Output $_ }
    throw 'Residual worker AppContainer ACL grants found.'
}
if ($workers.Count -gt 0) { throw 'Packaged Emumee processes remain after test runs.' }
if ($privateJournals.Count -gt 0) {
    $privateJournals | Select-Object -First 20 | ForEach-Object { Write-Output $_ }
    throw 'Private broker journal files remain after test runs.'
}
