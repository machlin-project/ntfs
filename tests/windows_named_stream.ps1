# Original ordinary-file ADS API regression; no volume/device/disk operations.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\windows_named_stream.ps1')
$directory = Join-Path $env:TEMP ('MachlinNamedStreamTest-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
$path = Join-Path $directory 'original.bin'
$original = [byte[]](7,3,0,255)
$payload = [byte[]](0,1,2,255,128,64)
$checks = 0
function Refuse([scriptblock]$Action) {
    $refused = $false
    try { & $Action | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'An unsafe/repeated stream request was accepted.' }
    $script:checks++
}
function Read-TestStream {
    $options = @{LiteralPath=$path;Stream='test-stream';ReadCount=0}
    # PowerShell 6+ replaced the Framework-only Encoding Byte with AsByteStream.
    if ((Get-Command Get-Content).Parameters.ContainsKey('AsByteStream')) {
        $options.AsByteStream = $true
    } else { $options.Encoding = 'Byte' }
    return [byte[]](Get-Content @options)
}
try {
    [IO.File]::WriteAllBytes($path,$original)
    $before = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    Write-CloudNamedStream $path 'test-stream' $payload
    $observed = [byte[]](Read-TestStream)
    if ([Convert]::ToBase64String($observed) -cne [Convert]::ToBase64String($payload)) {
        throw 'Original named stream bytes changed.'
    }
    $checks++
    Refuse { Write-CloudNamedStream $path 'test-stream' ([byte[]](9,9,9)) }
    $retained = [byte[]](Read-TestStream)
    if ([Convert]::ToBase64String($retained) -cne [Convert]::ToBase64String($payload) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $before) {
        throw 'A rejected duplicate changed the stream or original unnamed contents.'
    }
    $checks++
    foreach ($name in @('../escape','other:stream','with\separator','')) {
        Refuse { Write-CloudNamedStream $path $name $payload }
    }
    Refuse { Write-CloudNamedStream (Join-Path $directory 'absent.bin') 'test-stream' $payload }
    Refuse { Write-CloudNamedStream $directory 'test-stream' $payload }
    Refuse { Write-CloudNamedStream ($path + ':test-stream') 'nested' $payload }
} finally {
    [IO.Directory]::Delete($directory,$true)
}
Write-Output "PASS: $checks ordinary-file named-stream contracts; no native disk operations"
