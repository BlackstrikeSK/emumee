# Trusted guest entrypoint. Input and persona are supplied through observer stdin.
$ErrorActionPreference = 'Stop'
$guestPersona = [IO.File]::ReadAllText('/work/persona.json') | ConvertFrom-Json
$env:COMPUTERNAME = $guestPersona.hostname
$env:USERNAME = $guestPersona.user_name
$env:USERDOMAIN = $guestPersona.hostname
$env:USERPROFILE = 'C:\Users\' + $guestPersona.user_name
$env:SystemRoot = 'C:\Windows'
$env:windir = 'C:\Windows'
$env:PATH = '/opt/emumee/bin:' + $env:PATH
$guestPrograms = [IO.File]::ReadAllText('/opt/emumee/guest-tools.json') | ConvertFrom-Json
foreach ($guestProgram in $guestPrograms.program_names) {
    Set-Alias -Name $guestProgram -Value ('/opt/emumee/bin/' + $guestProgram) -Scope Global -Force
}
New-PSDrive -Name C -PSProvider FileSystem -Root '/opt/emumee/windows' | Out-Null
$ErrorActionPreference = 'Continue'
. '/work/input.ps1'
