# Pure transfer contracts; no device inspection, attachment or native recovery.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\windows_cloud_transport.ps1')
$directory = Join-Path $env:TEMP ('MachlinTransportTest-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
$checks = 0
function Refuse([scriptblock]$Action) {
    $refused = $false
    try { & $Action | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'Unsafe transfer was accepted.' }
    $script:checks++
}
try {
    $case = Join-Path $directory 'directory-full'
    [void][IO.Directory]::CreateDirectory($case)
    $payload = Join-Path $case 'input-directory-full.vhd'
    [IO.File]::WriteAllBytes($payload,[byte[]](1,2,3,4))
    $hash = (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = [pscustomobject]@{name='input-directory-full.vhd';bytes=4;sha256=$hash;
        path='C:\DO-NOT-READ\producer-machine-secret.vhd'}
    $actual = Resolve-CloudTransfer $directory 'unused-base.vhd' $expected
    $canonical = (Get-Item -LiteralPath $payload).FullName
    if ($actual -isnot [string] -or -not [string]::Equals($actual,$canonical,[StringComparison]::OrdinalIgnoreCase)) {
        throw ('Transfer local identity differs: expected [' + $canonical + '], actual [' + ($actual -join '; ') + '].')
    }
    $checks++
    # Filesystem APIs may normalize TEMP's drive case or short-path spelling.
    # The producer-local path remains deliberately nonexistent and is never read.
    $alias = Join-Path $directory '.'
    $aliased = Resolve-CloudTransfer $alias 'unused-base.vhd' $expected
    if ($aliased -isnot [string] -or -not [string]::Equals($aliased,$canonical,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'A normalized local package alias changed the selected file.'
    }
    $checks++
    $trap = [pscustomobject]@{name=$expected.name;bytes=$expected.bytes;sha256=$expected.sha256}
    Add-Member -InputObject $trap -MemberType ScriptProperty -Name path -Value {
        throw 'The producer-local path field must never be read.'
    }
    $trapped = Resolve-CloudTransfer $directory 'unused-base.vhd' $trap
    if ($trapped -isnot [string] -or -not [string]::Equals($trapped,$canonical,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Transfer ignored its consumer-local file identity.'
    }
    $checks++
    foreach ($name in @('../secret.vhd','input-..\secret.vhd','input-/escape.vhd','C:\secret.vhd','input-.vhd')) {
        $changed = $expected.PSObject.Copy(); $changed.name = $name
        Refuse { Resolve-CloudTransfer $directory 'unused-base.vhd' $changed }
    }
    foreach ($field in @('bytes','sha256')) {
        $changed = $expected.PSObject.Copy()
        $changed.$field = @{bytes=5;sha256=('0' * 64)}[$field]
        Refuse { Resolve-CloudTransfer $directory 'unused-base.vhd' $changed }
    }
    $destination = Join-Path $directory 'copied.vhd'
    Copy-CloudFile $payload $destination $hash
    $checks++
    Refuse { Copy-CloudFile $payload $destination $hash }
    Refuse { Copy-CloudFile $payload (Join-Path $directory 'changed.vhd') ('0' * 64) }
    foreach ($script in @('scripts\replay_windows_cloud.ps1','scripts\windows_cloud_transport.ps1',
        'tests\windows_image_recovery.ps1')) {
        $tokens = $null; $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot) $script),
            [ref]$tokens,[ref]$errors)
        if (@($errors).Count -ne 0) { throw ($script + ': ' + ($errors -join '; ')) }
        $checks++
    }
} finally {
    # Only the fresh private test directory is removed, never package inputs.
    [IO.Directory]::Delete($directory,$true)
}
Write-Output "PASS: $checks bounded transfer contracts; no native disk operations"
