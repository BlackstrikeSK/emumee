"""Benign dynamic-invocation fixtures with exact, independently known values.

Payloads only call a local reporting function and harmless guest utilities.
Run them exclusively through emumee.powershell's confined runner.
"""

import base64
import gzip


PRELUDE = r'''
$ErrorActionPreference = 'Stop'
function Invoke-ReadableProbe {
    [CmdletBinding()]
    param([string]$Case, [AllowEmptyString()][string]$Text,
          [AllowEmptyString()][string[]]$Items, [int]$Count, [switch]$Enabled)
    process { [Console]::WriteLine('PROBE=' + $Case) }
}
'''
TEXT = 'readable café 日本語 😀 "quoted" & <tag>\nsecond line'
ITEMS = ['space value', '', 'quote"value', 'café-✓']


def quote(value):
    return "'" + value.replace("'", "''") + "'"


def b64(value, encoding='utf-8'):
    return base64.b64encode(value.encode(encoding)).decode('ascii')


def decode(value):
    return "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(" + quote(b64(value)) + "))"


def invoke(case, name="'Invoke-ReadableProbe'", text=None, items=None):
    return ("& (" + name + ") -Case " + quote(case) + " -Text (" + (text or quote(TEXT)) +
            ") -Items " + (items or ('@(' + ','.join(map(quote, ITEMS)) + ')')) + " -Count ('4'+'2') -Enabled")


def compressed_layer(source, mode):
    encoded = base64.b64encode(gzip.compress(source.encode('utf-8'), mtime=0)).decode('ascii')
    expression = ("$ms=[IO.MemoryStream]::new([Convert]::FromBase64String(" + quote(encoded) + "));"
                  "$gz=[IO.Compression.GZipStream]::new($ms,[IO.Compression.CompressionMode]::Decompress);"
                  "$sr=[IO.StreamReader]::new($gz,[Text.Encoding]::UTF8);"
                  "$decoded=$sr.ReadToEnd();$sr.Dispose();$ms.Dispose();")
    return expression + ("Invoke-Expression $decoded" if mode % 2 else "& ([ScriptBlock]::Create($decoded))")


def cases():
    result = []

    def add(name, source, **extra):
        result.append({'name': name, 'source': PRELUDE + source,
                       'expected': {'Case': name, 'Text': TEXT, 'Items': ITEMS, 'Count': 42, 'Enabled': True}, **extra})

    add('baseline', invoke('baseline'))
    add('concatenation-format', "$cmd=('{1}-{0}' -f 'ReadableProbe','Invoke');$v=" +
        decode(TEXT) + ';' + invoke('concatenation-format', '$cmd', '$v'))
    integers = ','.join(str(ord(char)) for char in 'Invoke-ReadableProbe')
    add('character-codes-xor', "$cmd=-join ([char[]]@(" + integers + "));"
        "$bytes=[Convert]::FromBase64String(" + quote(base64.b64encode(bytes(x ^ 93 for x in TEXT.encode())).decode()) + ");"
        "for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=$bytes[$i] -bxor 93};"
        "$v=[Text.Encoding]::UTF8.GetString($bytes);" + invoke('character-codes-xor', '$cmd', '$v'))
    add('backticks-alias', "Set-Alias -Name rprobe -Value ('Invoke-'+'ReadableProbe');"
        "$v=" + decode(TEXT) + ';' + invoke('backticks-alias', "'rp'+'robe'", '$v') +
        "\nWr`ite-Out`put ('lexical-'+'backticks') | Out-Null")
    add('splat-conversion', "$p=@{Case='splat-conversion';Text=(" + decode(TEXT) + ");"
        "Items=@(" + ','.join(map(quote, ITEMS)) + ");Count='42';Enabled=$true};"
        "& (Get-Command ('Invoke-'+'ReadableProbe')) @p")
    add('pipeline-binding', r'''
function Invoke-PipelineProbe {
    [CmdletBinding()] param([Parameter(ValueFromPipeline)][string]$Text)
    process {
''' + invoke('pipeline-binding', text='$Text') + r'''
    }
}
''' + '(' + decode(TEXT) + ') | Invoke-PipelineProbe')
    add('scriptblock-create', '$script=' + decode(invoke('scriptblock-create')) + ';& ([ScriptBlock]::Create($script))')
    add('nested-expression', '$script=' + decode('Invoke-Expression (' + decode(invoke('nested-expression')) + ')') + ';iex $script')
    for depth in (8, 40, 120):
        name = f'compressed-{depth}-layers'
        source = invoke(name)
        for index in range(depth):
            source = compressed_layer(source, index)
        add(name, source, layers=depth)
    padding = 'benign-padding:' * 6000
    add('long-derived-source-line', '$v=(' + decode(padding + TEXT) + ').Substring(' +
        str(len(padding)) + ');' + invoke('long-derived-source-line', text='$v'))
    add('dot-source-decoded', '$script=' + decode(invoke('dot-source-decoded')) +
        ";[IO.File]::WriteAllText('/work/decoded-fixture.ps1',$script);. '/work/decoded-fixture.ps1'")
    add('new-runspace', '$nested=[PowerShell]::Create();try{[void]$nested.AddScript(' +
        decode(PRELUDE + invoke('new-runspace')) + ');$null=$nested.Invoke();'
        "if($nested.HadErrors){throw 'Nested runspace failed'}}finally{$nested.Dispose()}")
    child = PRELUDE + invoke('child-encoded-command')
    add('child-encoded-command', "& pwsh -NoLogo -NoProfile -NonInteractive -EncodedCommand " + quote(b64(child, 'utf-16le')) +
        ";if($LASTEXITCODE -ne 0){throw 'Child failed'}", child=True)
    source = invoke('native-argument-boundaries') + '\n& (\'/bin/\'+\'echo\') @(' + ','.join(map(quote, ITEMS)) + ')'
    add('native-argument-boundaries', source, native_arguments=ITEMS)
    add('persona-native-command', invoke('persona-native-command') +
        "\n$command=" + decode('reg.exe') + ";$a=@((" + decode('query') + "),(" +
        decode(r'HKCU\Control Panel\Desktop') + "),('/'+'v'),('Screen'+'SaveActive'));& $command @a",
        utility={'command': 'reg.exe', 'arguments': ['query', r'HKCU\Control Panel\Desktop', '/v', 'ScreenSaveActive']})
    add('dead-code-decoy', "if($false){" + invoke('never-executed-decoy') + '};' + invoke('dead-code-decoy'),
        forbidden_case='never-executed-decoy')
    uri = 'https://offline.invalid/a%20b?q=caf%C3%A9#part'
    add('typed-uri-headers', r'''
function Invoke-TypedProbe {
    [CmdletBinding()] param([string]$Case,[uri]$Uri,[hashtable]$Headers,[string]$Text)
    process { [Console]::WriteLine('PROBE=' + $Case) }
}
$opaque=[pscustomobject]@{Label='opaque-fixture'}
Add-Member -InputObject $opaque -MemberType ScriptProperty -Name Trap -Value {
    [Console]::WriteLine('SNAPSHOT-GETTER-RAN')
    'getter-value'
}
$headers=@{Agent=('readable '+'agent');Values=@('space value','','quote"value','café-✓');Opaque=$opaque;
           Id=[guid]::Parse('12345678-1234-5678-9abc-123456789abc');Version=[version]::new(2,3,4)}
''' + "& ('Invoke-'+'TypedProbe') -Case 'typed-uri-headers' -Uri (" + decode(uri) +
        ') -Headers $headers -Text (' + decode(TEXT) + ')',
        command='Invoke-TypedProbe', forbidden_output='SNAPSHOT-GETTER-RAN',
        expected={'Case':'typed-uri-headers', 'Uri':uri, 'Headers':{
            'Agent':'readable agent','Values':ITEMS,'Id':'12345678-1234-5678-9abc-123456789abc','Version':'2.3.4',
            'Opaque':{'type':'System.Management.Automation.PSCustomObject','capture_status':'opaque_value_not_evaluated'}}, 'Text':TEXT})
    web_uri = 'http://203.0.113.250/readable café 日本語 😀?q=space value'
    add('denied-obfuscated-webrequest', '$name=' + decode('Invoke-WebRequest') +
        ";$headers=@{'User-Agent'=('benign '+'fixture');'X-Case'='denied-obfuscated-webrequest'};"
        "$unexpected=$false;try{& $name -Uri (" + decode(web_uri) +
        ") -Headers $headers -TimeoutSec 1 -NoProxy;$unexpected=$true}"
        "catch{[Console]::WriteLine('PROBE=denied-obfuscated-webrequest')};"
        "if($unexpected){throw 'Offline request unexpectedly succeeded'}",
        command='Invoke-WebRequest', require_network_denial=True,
        expected={'Uri':web_uri,'Headers':{'User-Agent':'benign fixture','X-Case':'denied-obfuscated-webrequest'},
                  'ConnectionTimeoutSeconds':1,'NoProxy':True})
    return result
