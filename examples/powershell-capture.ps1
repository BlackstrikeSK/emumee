# Harmless fixture for `emumee powershell`; execute only through that runner.
$ErrorActionPreference = 'Stop'
$name = ('Write-' + 'Output')
$value = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('ZXZhbHVhdGVkLXZhbHVl'))
& $name $value
$splat = @{ InputObject = @('space value', 'café 日本語 😀', 'quote"value'); NoEnumerate = $true }
Write-Output @splat
Invoke-Expression ('Write-Output ' + "'nested-expression'")
function Invoke-CaptureFixture {
    [CmdletBinding()] param([Parameter(ValueFromPipeline)] [string]$Value)
    process { Write-Output $Value }
}
('pipeline-' + 'value') | Invoke-CaptureFixture
& '/bin/echo' @('space value', 'quote"value', '', 'café-✓')
try {
    $socket = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
    $socket.Dispose()
    throw 'Network socket unexpectedly allowed'
} catch [System.Management.Automation.MethodInvocationException] {
    Write-Output 'network-socket-denied'
}
