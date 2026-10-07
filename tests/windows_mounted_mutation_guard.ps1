param([string]$Collector, [string]$CollectorHash, [string]$Directory,
    [string]$BaseHash, [long]$BaseBytes)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ((Get-FileHash -LiteralPath $Collector -Algorithm SHA256).Hash.ToLowerInvariant() -ne $CollectorHash) {
    throw 'Collector source differs from the reviewed input.'
}
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Collector, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) { throw 'Collector parser errors.' }
foreach ($name in @('Test-NativeMountedMutationProfile', 'Initialize-NativeMountedMetadata')) {
    $functions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $false))
    if ($functions.Count -ne 1) { throw 'Collector function identity differs.' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
function New-MountedProfile {
    $security = [Security.AccessControl.RawSecurityDescriptor]::new('O:BAG:BAD:(A;OICI;FA;;;BA)')
    $descriptor = New-Object byte[] $security.BinaryLength
    $security.GetBinaryForm($descriptor, 0)
    $common = @{ present=$true; reference='281474976710680';
        lastWriteFileTime='134357146906613431'; changedFileTime='134357146906613431';
        securityDescriptor=[Convert]::ToBase64String($descriptor) }
    return [pscustomobject]@{ mountedMutationObjects=@(
        [pscustomobject](@{ relativePath='MachlinNativeMutation'; directory=$true } + $common),
        [pscustomobject](@{ relativePath='MachlinNativeMutation\right'; directory=$true } + $common),
        [pscustomobject](@{ relativePath='MachlinNativeMutation\right\final.bin'; directory=$false;
            bytes=65794; sha256=('0' * 64) } + $common),
        [pscustomobject]@{ relativePath='MachlinNativeMutation\left'; directory=$true; present=$false },
        [pscustomobject]@{ relativePath='MachlinNativeMutation\removed.bin'; directory=$false; present=$false },
        [pscustomobject]@{ relativePath='MachlinNativeMutation\reuse.bin'; directory=$false; present=$false },
        [pscustomobject]@{ relativePath='MachlinNativeMutation\right\moved'; directory=$true; present=$false }) }
}
$root = 'R:\MachlinWriteCases-native-write-alias-20261006'
$control = New-MountedProfile
if (@(Test-NativeMountedMutationProfile $control $root).Count -ne 7) {
    throw 'Positive mounted profile failed.'
}
$guards = @()
for ($index = 0; $index -lt 15; $index++) {
    $profile = New-MountedProfile
    $candidateRoot = $root
    $message = 'Unexpected mounted mutation metadata expectation.'
    switch ($index) {
        0 { $candidateRoot='T:\MachlinWriteCases-native-write-alias-20261006'; $message='Unexpected mounted mutation namespace profile.' }
        1 { $profile.mountedMutationObjects=$profile.mountedMutationObjects[0..5]; $message='Unexpected mounted mutation namespace profile.' }
        2 { $profile.mountedMutationObjects[0].relativePath='MachlinNativeMutation\..\resident.txt'; $message='Unexpected mounted mutation object identity or type.' }
        3 { $profile.mountedMutationObjects[0].directory='true'; $message='Unexpected mounted mutation object identity or type.' }
        4 { $profile.mountedMutationObjects[0].present=$false; $message='Unexpected mounted mutation object identity or type.' }
        5 { $profile.mountedMutationObjects[0].reference=[UInt64]281474976710680 }
        6 { $profile.mountedMutationObjects[0].reference='24'; $message='A sequence-bearing mounted identity is required.' }
        7 { $profile.mountedMutationObjects[0].lastWriteFileTime='not-decimal' }
        8 { $profile.mountedMutationObjects[0].changedFileTime='-1' }
        9 { $profile.mountedMutationObjects[0].securityDescriptor='AA=='; $message='Mounted mutation descriptor exceeds its bound.' }
        10 { $profile.mountedMutationObjects[2].bytes++; $message='Unexpected mounted mutation content expectation.' }
        11 { $profile.mountedMutationObjects[2].sha256='wrong'; $message='Unexpected mounted mutation content expectation.' }
        12 { $profile.mountedMutationObjects[4].present=$true; $message='Unexpected mounted mutation object identity or type.' }
        13 { $profile | Add-Member -NotePropertyName ordinaryObjects -NotePropertyValue @(); $message='Unexpected mounted mutation namespace profile.' }
        14 { $profile | Add-Member -NotePropertyName sequenceObjects -NotePropertyValue @(); $message='Unexpected mounted mutation namespace profile.' }
    }
    try {
        [void](Test-NativeMountedMutationProfile $profile $candidateRoot)
        throw 'Malformed mounted profile was accepted.'
    } catch {
        if ($_.Exception.Message -ne $message) { throw }
    }
    $guards += [ordered]@{ profile=$index; refused=$true; message=$message }
}
$folder = Get-Item -LiteralPath $Directory
if (-not $folder.PSIsContainer -or ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'A plain existing fixture directory is required.'
}
$base = Join-Path $Directory 'base.vhd'
$file = Get-Item -LiteralPath $base
if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $file.Length -ne $BaseBytes -or (Get-DiskImage -ImagePath $base).Attached -or
    (Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant() -ne $BaseHash) {
    throw 'Frozen base identity or detachment differs.'
}
if (@(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0 -or
    (Test-Path -LiteralPath 'R:\')) { throw 'Candidate drive letter is occupied.' }
Initialize-NativeMountedMetadata
$basic = [MachlinMountedMetadata]::Read($base)
$directoryInfo = [MachlinMountedMetadata]::Read($Directory)
if ($basic.LastWriteTime -ne $file.LastWriteTimeUtc.ToFileTimeUtc() -or
    $basic.ChangeTime -le 0 -or $directoryInfo.ChangeTime -le 0 -or
    (Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant() -ne $BaseHash -or
    (Get-DiskImage -ImagePath $base).Attached) {
    throw 'Read-only native metadata observation differs.'
}
return [ordered]@{ success=$true; parserErrors=0; positiveProfiles=1;
    malformedProfiles=$guards; fileAndDirectoryBasicInfoPassed=$true;
    baseLastWriteFileTime=$basic.LastWriteTime.ToString([Globalization.CultureInfo]::InvariantCulture);
    baseChangedFileTime=$basic.ChangeTime.ToString([Globalization.CultureInfo]::InvariantCulture);
    frozenBaseUnchanged=$true; frozenBaseDetached=$true; freeDriveLetter='R';
    nativeCandidateAttachments=0; lifecycleChanges=0 }
