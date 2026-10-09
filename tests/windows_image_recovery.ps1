# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Native NTFS recovery on individually identified disposable VHD fixtures.
param(
    [Parameter(Mandatory=$true)][string] $BatchManifest,
    [Parameter(Mandatory=$true)][string] $ReportName
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$nativeEventMaximumAttempts = 64
$nativeEventPollMilliseconds = 500
$fileBackedVirtualBusType = 15  # MSFT_Disk.BusType; use raw CIM rather than display text.
if ($ReportName -notmatch '^[A-Za-z0-9-]{1,96}$') { throw 'A bounded report name is required.' }
$reportPath = Join-Path $env:SystemRoot ('Temp\' + $ReportName + '.json')
if (Test-Path -LiteralPath $reportPath) { throw 'Retained reports must not be replaced.' }
$report = [ordered]@{ success=$false; stage='input-guards'; cases=@();
    startedUtc=[DateTime]::UtcNow.ToString('o'); fskitWritesQualified=$false;
    qualification='native NTFS VHD mount recovery; not cold boot or hardware power interruption' }
$candidate = $null
$attached = $false
$batch = $null

function Save-NativeSecurityComparison([string]$Profile, [string]$Path, $Entry,
                                      [string]$ExpectedSddl, [string]$ActualSddl) {
    # Successful rows are retained by the existing native checks. Preserve the
    # exact current comparison before its strict failure can unwind those rows.
    $report.lastSecurityComparison = [ordered]@{profile=$Profile;path=$Path;
        relativePath=$Entry.relativePath;reference=$Entry.reference;
        expectedSource=($Profile + '.securityDescriptor');
        expectedDescriptor=$Entry.securityDescriptor;expectedSddl=$ExpectedSddl;
        actualSource='Get-Acl.Sddl';actualSddl=$ActualSddl}
    $report | ConvertTo-Json -Depth 16 | Out-File -Encoding utf8 -LiteralPath $reportPath
}

function Assert-NativeCandidateDrive($ExpectedDisk, $ExpectedPartition) {
    $routes = @(Get-Partition -DriveLetter R -ErrorAction Stop)
    $disk = Get-Disk -Number $ExpectedDisk.Number
    if ($routes.Count -ne 1 -or $disk.IsBoot -or $disk.IsSystem -or
        [Guid]$disk.Guid -ne [Guid]$ExpectedDisk.Guid -or
        $routes[0].DiskNumber -ne $ExpectedDisk.Number -or
        $routes[0].PartitionNumber -ne $ExpectedPartition.PartitionNumber -or
        [Guid]$routes[0].Guid -ne [Guid]$ExpectedPartition.Guid -or
        $routes[0].Offset -ne $ExpectedPartition.Offset -or $routes[0].Size -ne $ExpectedPartition.Size -or
        $routes[0].IsBoot -or $routes[0].IsSystem) {
        throw 'Candidate R: route no longer names the admitted disk and partition.'
    }
}

function Test-NativeOrdinaryFiles($expected, [string]$root) {
    $descriptorHeaderBytes = 20
    $descriptorMaximumBytes = 65536
    $descriptorMaximumBase64Characters = 87384
    $contentMaximumBytes = 1048576
    $referenceHexDigits = 16
    $nativeFileIdHexDigits = 32
    $names = @('core-created.txt','core-renamed.txt','core-directory','core-directory\child.txt')
    $entries = @($expected.ordinaryObjects)
    if ($root -ne 'R:\MachlinWriteCases-native-write-alias-20261006' -or
        $entries.Count -ne $names.Count) { throw 'Unexpected ordinary namespace profile.' }
    $result = [ordered]@{ success=$false; checks=@(); rootNames=@(); directoryNames=@() }
    for ($index = 0; $index -lt $entries.Count; $index++) {
        $entry = $entries[$index]
        if ($entry.relativePath -cne $names[$index] -or $entry.present -isnot [bool] -or
            $entry.directory -isnot [bool] -or $entry.directory -ne ($index -eq 2)) {
            throw 'Unexpected ordinary object identity or type.'
        }
        $path = Join-Path $root $entry.relativePath
        $file = $null
        try { $file = Get-Item -LiteralPath $path -ErrorAction Stop }
        catch {
            if ($entry.present -or $_.Exception -isnot [System.Management.Automation.ItemNotFoundException]) {
                throw
            }
        }
        if (-not $entry.present) {
            if ($null -ne $file) { throw ('Unexpected ordinary object: ' + $entry.relativePath) }
            $result.checks += [ordered]@{ relativePath=$entry.relativePath; present=$false; passed=$true }
            continue
        }
        if ($null -eq $file -or $file.PSIsContainer -ne $entry.directory -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Ordinary object is missing, has the wrong type or is a reparse point.'
        }
        if ($entry.reference -notmatch '^[0-9]{1,20}$' -or
            $entry.lastWriteFileTime -notmatch '^[0-9]{1,20}$' -or
            $entry.securityDescriptor.Length -gt $descriptorMaximumBase64Characters -or
            $entry.securityDescriptor -notmatch '^[A-Za-z0-9+/=]+$') {
            throw 'Unexpected ordinary metadata expectation.'
        }
        $reference = [UInt64]::Parse($entry.reference,[Globalization.CultureInfo]::InvariantCulture)
        $expectedId = $reference.ToString(('x' + $referenceHexDigits),
            [Globalization.CultureInfo]::InvariantCulture).PadLeft($nativeFileIdHexDigits,'0')
        $fileId = @(& "$env:SystemRoot\System32\fsutil.exe" file queryfileid $path 2>&1)
        $idExit = $LASTEXITCODE
        $idText = $fileId -join "`n"
        if ($idExit -ne 0 -or $idText -notmatch '0x([0-9a-fA-F]{32})\s*$' -or
            $Matches[1].ToLowerInvariant() -ne $expectedId) { throw 'Ordinary sequence-bearing File ID differs.' }
        $time = $file.LastWriteTimeUtc.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
        if ($time -ne $entry.lastWriteFileTime) { throw 'Ordinary modified FILETIME differs.' }
        $descriptor = [Convert]::FromBase64String($entry.securityDescriptor)
        if ($descriptor.Length -lt $descriptorHeaderBytes -or
            $descriptor.Length -gt $descriptorMaximumBytes) { throw 'Ordinary descriptor exceeds its bound.' }
        $rawSecurity = [Security.AccessControl.RawSecurityDescriptor]::new($descriptor,0)
        if ($null -ne $rawSecurity.SystemAcl) { throw 'This native ordinary profile does not admit a SACL.' }
        $expectedAcl = $rawSecurity.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
        $actualAcl = (Get-Acl -LiteralPath $path).Sddl
        Save-NativeSecurityComparison 'ordinaryObjects' $path $entry $expectedAcl $actualAcl
        if ($actualAcl -ne $expectedAcl) { throw 'Ordinary native owner/group/DACL differs from the retained descriptor.' }
        $row = [ordered]@{ relativePath=$entry.relativePath; present=$true; directory=$file.PSIsContainer;
            reference=$entry.reference; fileId=[ordered]@{exitCode=$idExit;output=$fileId};
            lastWriteFileTime=$time; acl=$actualAcl; expectedAcl=$expectedAcl; passed=$false }
        if (-not $entry.directory) {
            if ($entry.bytes -lt 0 -or $entry.bytes -gt $contentMaximumBytes -or
                $entry.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Unexpected ordinary content expectation.' }
            $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($file.Length -ne $entry.bytes -or $digest -ne $entry.sha256) {
                throw ('Ordinary native content differs: ' + $entry.relativePath)
            }
            $row.bytes = $file.Length
            $row.sha256 = $digest
        }
        $row.passed = $true
        $result.checks += $row
    }
    $wantedRoot = @('child','initialized.bin','rename-after.txt','resident.txt')
    foreach ($entry in $entries) {
        if ($entry.present -and $entry.relativePath -notmatch '\\') { $wantedRoot += $entry.relativePath }
    }
    $actualRoot = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { $_.Name } | Sort-Object)
    $wantedRoot = @($wantedRoot | Sort-Object)
    if ($wantedRoot.Count -ne $actualRoot.Count -or ($wantedRoot.Count -ne 0 -and
        @(Compare-Object -ReferenceObject $wantedRoot -DifferenceObject $actualRoot -CaseSensitive).Count -ne 0)) {
        throw 'Ordinary root namespace differs.'
    }
    $result.rootNames = $actualRoot
    if ($entries[2].present) {
        $wantedChildren = @()
        if ($entries[3].present) { $wantedChildren += 'child.txt' }
        $actualChildren = @(Get-ChildItem -LiteralPath (Join-Path $root 'core-directory') -Force |
            ForEach-Object { $_.Name } | Sort-Object)
        if ($wantedChildren.Count -ne $actualChildren.Count -or ($wantedChildren.Count -ne 0 -and
            @(Compare-Object -ReferenceObject $wantedChildren -DifferenceObject $actualChildren -CaseSensitive).Count -ne 0)) {
            throw 'Ordinary child namespace differs.'
        }
        $result.directoryNames = $actualChildren
    } elseif ($entries[3].present) { throw 'A present child requires its directory.' }
    $result.success = $true
    return $result
}

function Test-NativeMountedMutationProfile($expected, [string]$root) {
    $names = @('MachlinNativeMutation', 'MachlinNativeMutation\right',
        'MachlinNativeMutation\right\final.bin', 'MachlinNativeMutation\left',
        'MachlinNativeMutation\removed.bin', 'MachlinNativeMutation\reuse.bin',
        'MachlinNativeMutation\right\moved')
    $directoryTypes = @($true, $true, $false, $true, $false, $false, $true)
    $entries = @($expected.mountedMutationObjects)
    $descriptorMaximumBytes = 4096
    $descriptorMaximumBase64Characters = 5464
    $descriptorHeaderBytes = 20
    $referenceSequenceShift = 48
    $nativePayloadBytes = 65537
    $nativeGapBytes = 257
    if ($root -cne 'R:\MachlinWriteCases-native-write-alias-20261006' -or
        $entries.Count -ne $names.Count -or
        $expected.PSObject.Properties.Name -contains 'ordinaryObjects' -or
        $expected.PSObject.Properties.Name -contains 'sequenceObjects') {
        throw 'Unexpected mounted mutation namespace profile.'
    }
    for ($index = 0; $index -lt $names.Count; $index++) {
        $entry = $entries[$index]
        if ($entry.relativePath -cne $names[$index] -or $entry.directory -isnot [bool] -or
            $entry.directory -ne $directoryTypes[$index] -or $entry.present -isnot [bool] -or
            $entry.present -ne ($index -lt 3)) {
            throw 'Unexpected mounted mutation object identity or type.'
        }
        if (-not $entry.present) { continue }
        if ($entry.reference -isnot [string] -or $entry.reference -notmatch '^[0-9]{1,20}$' -or
            $entry.lastWriteFileTime -isnot [string] -or $entry.lastWriteFileTime -notmatch '^[0-9]{1,20}$' -or
            $entry.changedFileTime -isnot [string] -or $entry.changedFileTime -notmatch '^[0-9]{1,20}$' -or
            $entry.securityDescriptor -isnot [string] -or
            $entry.securityDescriptor.Length -gt $descriptorMaximumBase64Characters -or
            $entry.securityDescriptor -notmatch '^[A-Za-z0-9+/=]+$') {
            throw 'Unexpected mounted mutation metadata expectation.'
        }
        $reference = [UInt64]::Parse($entry.reference, [Globalization.CultureInfo]::InvariantCulture)
        if (($reference -shr $referenceSequenceShift) -eq 0) { throw 'A sequence-bearing mounted identity is required.' }
        [void][DateTime]::FromFileTimeUtc([Int64]::Parse($entry.lastWriteFileTime,
            [Globalization.CultureInfo]::InvariantCulture))
        [void][DateTime]::FromFileTimeUtc([Int64]::Parse($entry.changedFileTime,
            [Globalization.CultureInfo]::InvariantCulture))
        $descriptor = [Convert]::FromBase64String($entry.securityDescriptor)
        if ($descriptor.Length -lt $descriptorHeaderBytes -or $descriptor.Length -gt $descriptorMaximumBytes) {
            throw 'Mounted mutation descriptor exceeds its bound.'
        }
        $security = [Security.AccessControl.RawSecurityDescriptor]::new($descriptor, 0)
        if ($null -ne $security.SystemAcl) { throw 'Mounted mutation SACL is outside this profile.' }
        if (-not $entry.directory -and ($entry.bytes -ne $nativePayloadBytes + $nativeGapBytes -or
            $entry.sha256 -notmatch '^[a-f0-9]{64}$')) {
            throw 'Unexpected mounted mutation content expectation.'
        }
    }
    return $entries
}

function Initialize-NativeMountedMetadata {
    if ('MachlinMountedMetadata' -as [type]) { return }
    # Public FILE_BASIC_INFO and GetFileInformationByHandleEx contract:
    # https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class MachlinMountedMetadata {
    private const uint FileReadAttributes = 0x80;
    private const uint ShareReadWriteDelete = 0x7;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private enum FileInfoByHandleClass { FileBasicInfo = 0 }
    [StructLayout(LayoutKind.Sequential)]
    public struct FileBasicInfo {
        public long CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
        public uint FileAttributes;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access,
        uint sharing, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,
        FileInfoByHandleClass information, out FileBasicInfo value, uint size);
    public static FileBasicInfo Read(string path) {
        using (SafeFileHandle handle = CreateFileW(path, FileReadAttributes,
            ShareReadWriteDelete, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics, IntPtr.Zero)) {
            if (handle.IsInvalid) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            FileBasicInfo value;
            if (!GetFileInformationByHandleEx(handle, FileInfoByHandleClass.FileBasicInfo,
                out value, (uint)Marshal.SizeOf(typeof(FileBasicInfo)))) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return value;
        }
    }
}
'@
}

function Test-NativeMountedMutationFiles($expected, [string]$root) {
    $entries = @(Test-NativeMountedMutationProfile $expected $root)
    Initialize-NativeMountedMetadata
    $referenceHexDigits = 16
    $fileIdHexDigits = 32
    $result = [ordered]@{ success=$false; checks=@(); namespaces=@() }
    foreach ($entry in $entries) {
        $path = Join-Path $root $entry.relativePath
        $item = $null
        try { $item = Get-Item -LiteralPath $path -ErrorAction Stop }
        catch {
            if ($entry.present -or $_.Exception -isnot [System.Management.Automation.ItemNotFoundException]) { throw }
        }
        if (-not $entry.present) {
            if ($null -ne $item) { throw 'A retired mounted mutation name is present.' }
            $result.checks += [ordered]@{ relativePath=$entry.relativePath; present=$false; passed=$true }
            continue
        }
        if ($null -eq $item -or $item.PSIsContainer -ne $entry.directory -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Mounted mutation object is missing or has the wrong type.'
        }
        $reference = [UInt64]::Parse($entry.reference, [Globalization.CultureInfo]::InvariantCulture)
        $expectedId = $reference.ToString(('x' + $referenceHexDigits), [Globalization.CultureInfo]::InvariantCulture).PadLeft($fileIdHexDigits, '0')
        $id = @(& "$env:SystemRoot\System32\fsutil.exe" file queryfileid $path 2>&1)
        $idExit = $LASTEXITCODE
        if ($idExit -ne 0 -or ($id -join "`n") -notmatch '0x([0-9a-fA-F]{32})\s*$' -or
            $Matches[1].ToLowerInvariant() -ne $expectedId) { throw 'Mounted sequence-bearing File ID differs.' }
        $basic = [MachlinMountedMetadata]::Read($path)
        $modified = $basic.LastWriteTime.ToString([Globalization.CultureInfo]::InvariantCulture)
        $changed = $basic.ChangeTime.ToString([Globalization.CultureInfo]::InvariantCulture)
        if ($modified -ne $entry.lastWriteFileTime -or $changed -ne $entry.changedFileTime) {
            throw 'Mounted modified/changed FILETIMEs differ.'
        }
        $security = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Convert]::FromBase64String($entry.securityDescriptor), 0)
        $wantedAcl = $security.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
        $actualAcl = (Get-Acl -LiteralPath $path).Sddl
        Save-NativeSecurityComparison 'mountedMutationObjects' $path $entry $wantedAcl $actualAcl
        if ($actualAcl -ne $wantedAcl) { throw 'Mounted native owner/group/DACL differs.' }
        $row = [ordered]@{ relativePath=$entry.relativePath; present=$true; directory=$entry.directory;
            reference=$entry.reference; fileId=[ordered]@{exitCode=$idExit;output=$id};
            lastWriteFileTime=$modified; changedFileTime=$changed; acl=$actualAcl; expectedAcl=$wantedAcl; passed=$false }
        if (-not $entry.directory) {
            $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($item.Length -ne $entry.bytes -or $digest -ne $entry.sha256) { throw 'Mounted final file bytes differ.' }
            $row.bytes = $item.Length
            $row.sha256 = $digest
        }
        $row.passed = $true
        $result.checks += $row
    }
    foreach ($directory in @('', 'MachlinNativeMutation', 'MachlinNativeMutation\right')) {
        $wanted = switch ($directory) {
            '' { @('child', 'initialized.bin', 'MachlinNativeMutation', 'rename-after.txt', 'resident.txt') }
            'MachlinNativeMutation' { @('right') }
            'MachlinNativeMutation\right' { @('final.bin') }
        }
        $path = if ($directory -eq '') { $root } else { Join-Path $root $directory }
        $actual = @(Get-ChildItem -LiteralPath $path -Force | ForEach-Object { $_.Name } | Sort-Object)
        $wanted = @($wanted | Sort-Object)
        if ($actual.Count -ne $wanted.Count -or
            @(Compare-Object -ReferenceObject $wanted -DifferenceObject $actual -CaseSensitive).Count -ne 0) {
            throw 'Mounted mutation namespace differs.'
        }
        $result.namespaces += [ordered]@{ relativePath=$directory; names=$actual; passed=$true }
    }
    $result.success = $true
    return $result
}

function Test-NativeSequenceProfile($expected, [string]$root) {
    $objectMaximum = 322
    $pressureNameUnits = 180
    $pressureMaximum = 320
    $replacementMaximum = 80
    $descriptorMaximumBase64Characters = 87384
    $descriptorHeaderBytes = 20
    $descriptorMaximumBytes = 65536
    $contentMaximumBytes = 1048576
    $entries = @($expected.sequenceObjects)
    if (($root -cne 'R:\MachlinWriteCases-native-write-alias-20261006' -and
         $root -cnotmatch '^R:\\MachlinCloudNTFS-[0-9a-f]{32}$') -or
        $entries.Count -lt 2 -or $entries.Count -gt $objectMaximum) {
        throw 'Unexpected sequence namespace profile.'
    }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $directories = @{}
    foreach ($entry in $entries) {
        if ($entry.relativePath -isnot [string] -or $entry.present -isnot [bool] -or
            $entry.directory -isnot [bool] -or -not $names.Add($entry.relativePath)) {
            throw 'Unexpected sequence object identity or type.'
        }
        $name = $entry.relativePath
        if ($entry.directory) {
            if ($name -cne 'native-growth' -and $name -cne 'native-move') {
                throw 'Unexpected sequence directory.'
            }
            $directories[$name] = $entry.present
        } else {
            $allowed = $false
            if ($name -cmatch '^native-growth\\pressure-([0-9]{4})-(n+)$') {
                $allowed = [int]$Matches[1] -lt $pressureMaximum -and
                    ($name.Substring('native-growth\'.Length)).Length -eq $pressureNameUnits
            } elseif ($name -cmatch '^native-growth\\replacement-([0-9]{4})$') {
                $allowed = [int]$Matches[1] -lt $replacementMaximum
            } elseif ($name -ceq 'native-growth\sustained-file' -or
                $name -ceq 'native-move\sustained-renamed' -or
                $name -ceq 'native-move\replace-target') {
                $allowed = $true
            }
            if (-not $allowed -or -not $entry.present) { throw 'Unexpected sequence filename.' }
        }
        if (-not $entry.present) { continue }
        if ($entry.reference -isnot [string] -or $entry.reference -notmatch '^[0-9]{1,20}$' -or
            $entry.lastWriteFileTime -isnot [string] -or $entry.lastWriteFileTime -notmatch '^[0-9]{1,20}$' -or
            $entry.securityDescriptor -isnot [string] -or
            $entry.securityDescriptor.Length -gt $descriptorMaximumBase64Characters -or
            $entry.securityDescriptor -notmatch '^[A-Za-z0-9+/=]+$') {
            throw 'Unexpected sequence metadata expectation.'
        }
        if (-not $entry.directory -and (($entry.bytes -isnot [int] -and $entry.bytes -isnot [long]) -or
            $entry.bytes -lt 0 -or $entry.bytes -gt $contentMaximumBytes -or
            $entry.sha256 -isnot [string] -or $entry.sha256 -notmatch '^[a-f0-9]{64}$')) {
            throw 'Unexpected sequence content expectation.'
        }
        [void][UInt64]::Parse($entry.reference,[Globalization.CultureInfo]::InvariantCulture)
        [void][DateTime]::FromFileTimeUtc([Int64]::Parse($entry.lastWriteFileTime,
            [Globalization.CultureInfo]::InvariantCulture))
        $descriptor = [Convert]::FromBase64String($entry.securityDescriptor)
        if ($descriptor.Length -lt $descriptorHeaderBytes -or $descriptor.Length -gt $descriptorMaximumBytes) {
            throw 'Sequence descriptor exceeds its bound.'
        }
        $rawSecurity = [Security.AccessControl.RawSecurityDescriptor]::new($descriptor,0)
        if ($null -ne $rawSecurity.SystemAcl) { throw 'This native sequence profile does not admit a SACL.' }
    }
    if ($directories.Count -ne 2) { throw 'Both sequence directory expectations are required.' }
    foreach ($entry in $entries) {
        if (-not $entry.directory -and -not $directories[$entry.relativePath.Split('\')[0]]) {
            throw 'A sequence child requires its present directory.'
        }
    }
    return $entries
}

function Test-NativeSequenceFiles($expected, [string]$root) {
    $descriptorHeaderBytes = 20
    $descriptorMaximumBytes = 65536
    $referenceHexDigits = 16
    $nativeFileIdHexDigits = 32
    $entries = @(Test-NativeSequenceProfile $expected $root)
    $result = [ordered]@{ success=$false; checks=@(); rootNames=@(); directoryNames=@{} }
    foreach ($entry in $entries) {
        $path = Join-Path $root $entry.relativePath
        $file = $null
        try { $file = Get-Item -LiteralPath $path -ErrorAction Stop }
        catch {
            if ($entry.present -or $_.Exception -isnot [System.Management.Automation.ItemNotFoundException]) {
                throw
            }
        }
        if (-not $entry.present) {
            if ($null -ne $file) { throw 'Unexpected sequence directory remains present.' }
            $result.checks += [ordered]@{ relativePath=$entry.relativePath; present=$false; passed=$true }
            continue
        }
        if ($null -eq $file -or $file.PSIsContainer -ne $entry.directory -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Sequence object is missing, has the wrong type or is a reparse point.'
        }
        $reference = [UInt64]::Parse($entry.reference,[Globalization.CultureInfo]::InvariantCulture)
        $expectedId = $reference.ToString(('x' + $referenceHexDigits),
            [Globalization.CultureInfo]::InvariantCulture).PadLeft($nativeFileIdHexDigits,'0')
        $fileId = @(& "$env:SystemRoot\System32\fsutil.exe" file queryfileid $path 2>&1)
        $idExit = $LASTEXITCODE
        if ($idExit -ne 0 -or ($fileId -join "`n") -notmatch '0x([0-9a-fA-F]{32})\s*$' -or
            $Matches[1].ToLowerInvariant() -ne $expectedId) { throw 'Sequence-bearing File ID differs.' }
        $time = $file.LastWriteTimeUtc.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
        if ($time -ne $entry.lastWriteFileTime) { throw 'Sequence modified FILETIME differs.' }
        $descriptor = [Convert]::FromBase64String($entry.securityDescriptor)
        if ($descriptor.Length -lt $descriptorHeaderBytes -or $descriptor.Length -gt $descriptorMaximumBytes) {
            throw 'Sequence descriptor exceeds its bound.'
        }
        $rawSecurity = [Security.AccessControl.RawSecurityDescriptor]::new($descriptor,0)
        if ($null -ne $rawSecurity.SystemAcl) { throw 'This native sequence profile does not admit a SACL.' }
        $expectedAcl = $rawSecurity.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
        $actualAcl = (Get-Acl -LiteralPath $path).Sddl
        Save-NativeSecurityComparison 'sequenceObjects' $path $entry $expectedAcl $actualAcl
        if ($actualAcl -ne $expectedAcl) { throw 'Sequence native owner/group/DACL differs.' }
        $row = [ordered]@{ relativePath=$entry.relativePath; present=$true; directory=$file.PSIsContainer;
            reference=$entry.reference; fileId=[ordered]@{exitCode=$idExit;output=$fileId};
            lastWriteFileTime=$time; acl=$actualAcl; expectedAcl=$expectedAcl; passed=$false }
        if (-not $entry.directory) {
            $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($file.Length -ne $entry.bytes -or $digest -ne $entry.sha256) {
                throw ('Sequence native content differs: ' + $entry.relativePath)
            }
            $row.bytes = $file.Length
            $row.sha256 = $digest
        }
        $row.passed = $true
        $result.checks += $row
    }
    $wantedRoot = @('child','initialized.bin','rename-after.txt','resident.txt')
    foreach ($entry in $entries) {
        if ($entry.directory -and $entry.present) {
            $wantedRoot += $entry.relativePath
            $prefix = $entry.relativePath + '\'
            $wanted = @($entries | Where-Object { -not $_.directory -and $_.relativePath.StartsWith($prefix) } |
                ForEach-Object { $_.relativePath.Substring($prefix.Length) } | Sort-Object)
            $actual = @(Get-ChildItem -LiteralPath (Join-Path $root $entry.relativePath) -Force |
                ForEach-Object { $_.Name } | Sort-Object)
            if ($wanted.Count -ne $actual.Count -or ($wanted.Count -gt 0 -and
                @(Compare-Object -ReferenceObject $wanted -DifferenceObject $actual -CaseSensitive).Count -ne 0)) {
                throw 'Sequence child namespace differs.'
            }
            $result.directoryNames[$entry.relativePath] = $actual
        }
    }
    $wantedRoot = @($wantedRoot | Sort-Object)
    $actualRoot = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { $_.Name } | Sort-Object)
    if ($wantedRoot.Count -ne $actualRoot.Count -or
        @(Compare-Object -ReferenceObject $wantedRoot -DifferenceObject $actualRoot -CaseSensitive).Count -ne 0) {
        throw 'Sequence root namespace differs.'
    }
    $result.rootNames = $actualRoot
    $result.success = $true
    return $result
}

function Test-NativeFiles($expected, [string]$root, [string]$acl, $fileId) {
    if (($root -notmatch '^[TR]:\\MachlinWriteCases-native-write-alias-20261006$' -and
         $root -cnotmatch '^R:\\MachlinCloudNTFS-[0-9a-f]{32}$') -or
        @($expected.files).Count -ne 4) { throw 'Unexpected workload root or count.' }
    $result = [ordered]@{ checks=@(); success=$false }
    foreach ($entry in $expected.files) {
        if ($entry.relativePath -notmatch '^(initialized\.bin|rename-after\.txt|resident\.txt|child\\nested\.txt)$' -or
            $entry.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Unexpected workload entry.' }
        $path = Join-Path $root $entry.relativePath
        $file = Get-Item -LiteralPath $path
        $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($file.Length -ne $entry.bytes -or $digest -ne $entry.sha256) { throw ('Native content mismatch: ' + $entry.relativePath) }
        $result.checks += [ordered]@{ relativePath=$entry.relativePath; bytes=$file.Length; sha256=$digest; passed=$true }
        if ($entry.PSObject.Properties.Name -contains 'lastWriteFileTime') {
            $time = $file.LastWriteTimeUtc.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
            if ($time -ne $entry.lastWriteFileTime) { throw 'Native file time mismatch.' }
            $result.checks[-1]['lastWriteFileTime'] = $time
            $result.lastWriteTime = [ordered]@{ fileTime=$time; expectedFileTime=$entry.lastWriteFileTime; passed=$true }
        }
    }
    $stream = $expected.namedStream
    if ($stream.relativePath -ne 'resident.txt' -or $stream.name -ne 'original-stream' -or $stream.bytes -ne 29) {
        throw 'Unexpected named stream.'
    }
    $bytes = [byte[]](Get-Content -LiteralPath (Join-Path $root $stream.relativePath) -Stream $stream.name -Encoding Byte -ReadCount 0)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $streamHash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($bytes.Length -ne $stream.bytes -or $streamHash -ne $stream.sha256) { throw 'Native named stream mismatch.' }
    $result.namedStream = [ordered]@{ bytes=$bytes.Length; sha256=$streamHash; passed=$true }
    $target = Join-Path $root 'initialized.bin'
    $actualAcl = (Get-Acl -LiteralPath $target).Sddl
    $actualFileId = @(& "$env:SystemRoot\System32\fsutil.exe" file queryfileid $target 2>&1)
    $exit = $LASTEXITCODE
    if ($actualAcl -ne $acl -or $exit -ne 0 -or
        ($actualFileId -join "`n") -ne ($fileId.output -join "`n")) { throw 'Native ACL or file identity changed.' }
    $result.targetAcl = $actualAcl
    $result.fileId = [ordered]@{ exitCode=$exit; output=$actualFileId }
    $residentIdentityDeclared = $expected.PSObject.Properties.Name -contains 'residentFileId'
    $residentAclDeclared = $expected.PSObject.Properties.Name -contains 'residentAcl'
    if ($residentIdentityDeclared -ne $residentAclDeclared) { throw 'Incomplete expected resident identity.' }
    if ($residentIdentityDeclared) {
        $residentPath = Join-Path $root 'resident.txt'
        $residentAcl = (Get-Acl -LiteralPath $residentPath).Sddl
        $residentFileId = @(& "$env:SystemRoot\System32\fsutil.exe" file queryfileid $residentPath 2>&1)
        $residentIdExit = $LASTEXITCODE
        if ($residentAcl -ne $expected.residentAcl -or $residentIdExit -ne 0 -or
            ($residentFileId -join "`n") -ne ($expected.residentFileId.output -join "`n")) {
            throw 'Native resident ACL or file identity changed.'
        }
        $residentTime = (Get-Item -LiteralPath $residentPath).LastWriteTimeUtc.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
        $result.resident = [ordered]@{ acl=$residentAcl; fileId=[ordered]@{exitCode=$residentIdExit;output=$residentFileId};lastWriteFileTime=$residentTime;passed=$true }
    }
    if ($expected.PSObject.Properties.Name -contains 'ordinaryObjects') {
        if ($expected.PSObject.Properties.Name -contains 'sequenceObjects') { throw 'Conflicting native namespace profiles.' }
        $result.ordinary = Test-NativeOrdinaryFiles $expected $root
    }
    if ($expected.PSObject.Properties.Name -contains 'sequenceObjects') {
        $result.sequence = Test-NativeSequenceFiles $expected $root
    }
    if ($expected.PSObject.Properties.Name -contains 'mountedMutationObjects') {
        $result.mountedMutation = Test-NativeMountedMutationFiles $expected $root
    }
    $result.success = $true
    return $result
}

function Test-OriginalDisk {
    if ($batch.PSObject.Properties.Name -contains 'cloudInput') {
        # The cloud baseline remains detached and immutable throughout this run.
        # Its complete native namespace/corpus is reviewed before packaging.
        $path = Join-Path $batch.directory 'base.vhd'
        if ($batch.cloudInput -isnot [bool] -or -not $batch.cloudInput -or
            (Get-DiskImage -ImagePath $path).Attached -or
            (Get-Item -LiteralPath $path).Length -ne $batch.baseVhdBytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $batch.baseVhdSha256) {
            throw 'Detached cloud baseline identity changed.'
        }
        return [ordered]@{success=$true;baselineDetached=$true;sha256=$batch.baseVhdSha256;
            namespaceSource='original Windows native corpus; no baseline remount'}
    }
    $disk = Get-Disk -Number 1
    $partition = Get-Partition -DriveLetter T
    $volume = Get-Volume -DriveLetter T
    if ($disk.Size -ne 8589934592 -or $disk.IsBoot -or $disk.IsSystem -or
        $disk.IsOffline -or $disk.IsReadOnly -or $disk.PartitionStyle -ne 'GPT' -or
        $disk.SerialNumber -ne '29494EE0-8857-4968-8_00000001.' -or
        $partition.DiskNumber -ne 1 -or $partition.PartitionNumber -ne 2 -or
        $partition.Offset -ne 16777216 -or $partition.Size -ne 8572108800 -or
        $partition.Guid -ne '{8379514a-8036-4690-a793-40f21b124720}' -or
        $volume.FileSystemType -ne 'NTFS' -or $volume.FileSystemLabel -ne 'MachlinNTFS') {
        throw 'The original disposable test disk identity changed.'
    }
    return (Test-NativeFiles $batch.baseline $batch.baseline.root $batch.targetAcl $batch.fileId)
}

function Test-NativeTornMetadataProfile($product, [string]$root) {
    $pageMaximum = 16
    $sectorBytes = 512
    $pageBytes = 4096
    $mftRecordBytes = 1024
    $mftBytesMaximum = 1048576
    $indexBytesMaximum = 16777216
    $sequenceMaximum = 65535
    $recordMask = [UInt64]281474976710655
    $fields = @('FileName','FileReference','BufferOffset','TornStructureOffset',
                'BlockIndex','ExpectedSequenceNumber','ActualSequenceNumber')
    if ($product.PSObject.Properties.Name -notcontains 'expectedTornMetadataPages') { return @() }
    if (($root -cne 'R:\MachlinWriteCases-native-write-alias-20261006' -and
         $root -cnotmatch '^R:\\MachlinCloudNTFS-[0-9a-f]{32}$') -or
        $product.PSObject.Properties.Name -notcontains 'sequenceObjects') {
        throw 'Unexpected torn metadata namespace.'
    }
    $pages = @($product.expectedTornMetadataPages)
    if ($pages.Count -gt $pageMaximum) { throw 'Torn metadata profile exceeds its bound.' }
    $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($page in $pages) {
        if (@($page.PSObject.Properties).Count -ne $fields.Count) { throw 'Unexpected torn metadata fields.' }
        foreach ($field in $fields) {
            if ($page.PSObject.Properties.Name -notcontains $field -or $page.$field -isnot [string]) {
                throw 'Unexpected torn metadata field type.'
            }
        }
        foreach ($field in $fields | Where-Object { $_ -ne 'FileName' }) {
            if ($page.$field -notmatch '^(0|[1-9][0-9]{0,15})$') { throw 'Unexpected torn metadata number.' }
        }
        $blocks = $mftRecordBytes / $sectorBytes
        $bytesMaximum = $mftBytesMaximum
        if ($page.FileName -ceq '\$Mft') {
            if ($page.FileReference -cne '0') { throw 'Unexpected torn MFT identity.' }
        } elseif ($page.FileName -ceq '\$MftMirr') {
            if ($page.FileReference -cne '1') { throw 'Unexpected torn mirror identity.' }
        } elseif ($page.FileName -ceq ('\' + $root.Substring('R:\'.Length) + '\native-growth')) {
            $parent = @($product.sequenceObjects | Where-Object {
                $_.relativePath -ceq 'native-growth' -and $_.directory -and $_.present
            })
            if ($parent.Count -ne 1 -or
                [UInt64]$page.FileReference -ne ([UInt64]$parent[0].reference -band $recordMask)) {
                throw 'Unexpected torn index identity.'
            }
            $blocks = $pageBytes / $sectorBytes
            $bytesMaximum = $indexBytesMaximum
        } else { throw 'Unexpected torn metadata stream.' }
        if ([UInt64]$page.BufferOffset -ge $bytesMaximum -or [UInt64]$page.BufferOffset % $pageBytes -ne 0 -or
            $page.TornStructureOffset -cne '0' -or [UInt64]$page.BlockIndex -ge $blocks -or
            [UInt64]$page.ExpectedSequenceNumber -lt 1 -or [UInt64]$page.ExpectedSequenceNumber -gt $sequenceMaximum -or
            [UInt64]$page.ActualSequenceNumber -gt $sequenceMaximum -or
            $page.ExpectedSequenceNumber -ceq $page.ActualSequenceNumber) {
            throw 'Unexpected torn metadata sector state.'
        }
        $key = ($fields | ForEach-Object { $page.$_ }) -join '|'
        if (-not $keys.Add($key)) { throw 'Duplicate torn metadata expectation.' }
    }
    return $pages
}

function Test-NativeTornWriteEvent($data, $product) {
    $fields = @('FileName','FileReference','BufferOffset','TornStructureOffset',
                'BlockIndex','ExpectedSequenceNumber','ActualSequenceNumber')
    foreach ($field in $fields) {
        if (-not $data.ContainsKey($field)) { throw 'Incomplete native torn-write event.' }
    }
    if ($data['FileName'] -ceq '\$LogFile') {
        if ($data['FileReference'] -cne '2' -or $data['TornStructureOffset'] -cne '0' -or
            $product.PSObject.Properties.Name -notcontains 'expectedTornLogPages') {
            throw 'Unattributed native torn-write event requires review.'
        }
        $expected = @($product.expectedTornLogPages | Where-Object {
            $_.bufferOffset -ceq $data['BufferOffset'] -and $_.blockIndex -ceq $data['BlockIndex'] -and
            $_.expectedSequenceNumber -ceq $data['ExpectedSequenceNumber'] -and
            $_.actualSequenceNumber -ceq $data['ActualSequenceNumber']
        })
        if ($expected.Count -ne 1) { throw 'Native torn-page observation differs from the injected sector state.' }
        return 'journal'
    }
    $pages = @(Test-NativeTornMetadataProfile $product $product.root)
    $matchingPages = @($pages | Where-Object {
        $page = $_
        @($fields | Where-Object { $page.$_ -cne $data[$_] }).Count -eq 0
    })
    if ($matchingPages.Count -ne 1) { throw 'Native torn metadata observation differs from the injected sector state.' }
    return 'metadata'
}

function Get-NativeEvents([DateTime]$since, [string]$volumeId, $product, $observation) {
    $utc = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    $result = @()
    foreach ($provider in @('Microsoft-Windows-Ntfs','Microsoft-Windows-Wininit','Microsoft-Windows-Chkdsk')) {
        $channel = if ($provider -eq 'Microsoft-Windows-Ntfs') { 'System' } else { 'Application' }
        $query = "*[System[Provider[@Name='$provider'] and TimeCreated[@SystemTime >= '$utc']]]"
        $output = @(& "$env:SystemRoot\System32\wevtutil.exe" qe $channel "/q:$query" /f:xml /e:Events /c:256 /rd:true 2>&1)
        $exit = $LASTEXITCODE
        $row = [ordered]@{ provider=$provider; channel=$channel; query=$query; exitCode=$exit;
                           output=$output; parsed=$false; count=$null; matchingHealthyEvents=@();
                           matchingInjectedTornPages=@(); matchingInjectedMetadataPages=@(); observedEvents=@() }
        # Preserve the exact native query before parsing or applying verdicts.
        $observation.nativeEvents += $row
        if ($exit -ne 0) { throw ('Native event query failed: ' + $provider) }
        [xml]$xml = ($output -join "`n").Replace([string][char]0,'')
        $events = @($xml.SelectNodes("//*[local-name()='Event']"))
        $row.parsed = $true
        $row.count = $events.Count
        if ($events.Count -ge 256) { throw 'Native event report reached its observation bound.' }
        if ($provider -ne 'Microsoft-Windows-Ntfs' -and $events.Count -ne 0) { throw 'Native repair-provider event requires review.' }
        foreach ($event in $events) {
            $system = $event.SelectSingleNode("*[local-name()='System']")
            $time = [DateTime]::Parse($system.SelectSingleNode("*[local-name()='TimeCreated']").GetAttribute('SystemTime'),
                                    [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
            if ($time.ToUniversalTime() -lt $since.ToUniversalTime() -or
                $system.SelectSingleNode("*[local-name()='Provider']").GetAttribute('Name') -ne $provider) {
                throw 'Native event identity/time mismatch.'
            }
            $id = [int]$system.SelectSingleNode("*[local-name()='EventID']").InnerText
            $level = [int]$system.SelectSingleNode("*[local-name()='Level']").InnerText
            $data = @{}
            foreach ($field in $event.SelectNodes("*[local-name()='EventData']/*[local-name()='Data']")) {
                $data[$field.GetAttribute('Name')] = $field.InnerText
            }
            $observed = [ordered]@{ eventId=$id; level=$level; fields=$data;
                                   systemTimeUtc=$time.ToUniversalTime().ToString('o') }
            $row.observedEvents += $observed
            if ($id -eq 100) { throw 'Native NTFS repair event requires review.' }
            $matching = ($data.ContainsKey('DriveName') -and
                ($data['DriveName'] -eq 'R:' -or $data['DriveName'].TrimEnd('\') -eq $volumeId.TrimEnd('\'))) -or
                ($data.ContainsKey('VolumeName') -and $data['VolumeName'].TrimEnd('\') -eq $volumeId.TrimEnd('\'))
            if ($id -eq 7) {
                if ($level -ne 3 -or -not $matching) {
                    throw 'Unattributed native torn-write event requires review.'
                }
                $kind = Test-NativeTornWriteEvent $data $product
                if ($kind -ceq 'journal') { $row.matchingInjectedTornPages += $observed }
                else { $row.matchingInjectedMetadataPages += $observed }
            } elseif ($matching) {
                if ($id -ne 98 -or -not $data.ContainsKey('CorruptionActionState') -or $data['CorruptionActionState'] -ne '0') {
                    throw 'Native candidate corruption state requires review.'
                }
                $row.matchingHealthyEvents += $observed
            } elseif ($level -le 3 -and $level -ne 0) {
                throw 'An unclassified native warning or error requires review.'
            }
        }
        $result += $row
    }
    return $result
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Native VHD mount requires the authorized administrative context.' }
    $report.identity = $identity.Name
    if ((Get-Item -LiteralPath $BatchManifest).Length -gt 8388608) { throw 'Batch input exceeds its bound.' }
    $batch = Get-Content -LiteralPath $BatchManifest -Raw | ConvertFrom-Json
    $diskBytes = [long]8589934592
    $partitionOffset = [long]16777216
    $partitionBytes = [long]8572108800
    $partitionNumber = 2
    $volumeLabel = 'MachlinNTFS'
    $protectedDiskNumbers = @((Get-Disk).Number)
    if ($batch.PSObject.Properties.Name -contains 'cloudInput') {
        if ($batch.cloudInput -isnot [bool] -or -not $batch.cloudInput -or
            $batch.bootstrapSha256 -notmatch '^[a-f0-9]{64}$' -or
            $batch.baseline.root -cnotmatch '^R:\\MachlinCloudNTFS-[0-9a-f]{32}$' -or
            $batch.diskBytes -lt 134217728 -or $batch.diskBytes -gt 4294967296 -or
            $batch.diskBytes % 1048576 -ne 0 -or $batch.partitionOffset -lt 1048576 -or
            $batch.partitionBytes -le 0 -or $batch.partitionOffset % 512 -ne 0 -or
            $batch.partitionBytes % 512 -ne 0 -or $batch.partitionOffset -ge $batch.diskBytes -or
            $batch.partitionBytes -gt $batch.diskBytes - $batch.partitionOffset -or
            $batch.partitionNumber -lt 1 -or $batch.partitionNumber -gt 128 -or
            $batch.volumeLabel -cne 'MachlinCloudNTFS') { throw 'Unexpected cloud input identity or geometry.' }
        $diskBytes = [long]$batch.diskBytes
        $partitionOffset = [long]$batch.partitionOffset
        $partitionBytes = [long]$batch.partitionBytes
        $partitionNumber = [int]$batch.partitionNumber
        $volumeLabel = $batch.volumeLabel
        foreach ($product in $batch.products) {
            if ($product.root -cne $batch.baseline.root -or
                $product.PSObject.Properties.Name -notcontains 'sequenceObjects' -or
                $product.PSObject.Properties.Name -notcontains 'preparedVhdName') {
                throw 'Cloud candidates must use their exact native baseline and prepared sequence profile.'
            }
        }
    }
    if ($batch.directory -notmatch '^C:\\Windows\\Temp\\MachlinNTFSImageRecovery-[A-Za-z0-9-]{1,48}$' -or
        @($batch.products).Count -lt 1 -or @($batch.products).Count -gt 256) { throw 'Unexpected private fixture directory or count.' }
    # Admit every declared mounted profile before constructing or attaching any
    # disposable candidate. This validation performs no filesystem mutation.
    foreach ($product in $batch.products) {
        [void](Test-NativeTornMetadataProfile $product $product.root)
        if ($product.PSObject.Properties.Name -contains 'mountedMutationObjects') {
            [void](Test-NativeMountedMutationProfile $product $product.root)
            Initialize-NativeMountedMetadata
        }
    }
    $folder = Get-Item -LiteralPath $batch.directory
    if (-not $folder.PSIsContainer -or ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'A plain fixture directory is required.' }
    $base = Join-Path $batch.directory 'base.vhd'
    $baseFile = Get-Item -LiteralPath $base
    if ($baseFile.PSIsContainer -or ($baseFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $baseFile.Length -ne $batch.baseVhdBytes -or
        (Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant() -ne $batch.baseVhdSha256) { throw 'Base VHD bytes disagree.' }
    if ((Get-PSDrive -Name C).Free -lt (@($batch.products).Count + 1) * $batch.baseVhdBytes + 1073741824) { throw 'Insufficient guest fixture storage.' }
    if (@(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0 -or
        (Test-Path -LiteralPath 'R:\')) { throw 'The candidate drive letter is already in use.' }
    $report.os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime
    $report.originalBefore = Test-OriginalDisk
    $report.stage = 'native-candidate-recovery'
    foreach ($product in $batch.products) {
        if ($product.case -notmatch '^[A-Za-z0-9-]{1,80}$' -or $product.expectedVhdSha256 -notmatch '^[a-f0-9]{64}$' -or
            @($product.patches).Count -gt 32) { throw 'Candidate manifest exceeds its bounds.' }
        $candidate = Join-Path $batch.directory ($product.case + '.vhd')
        if (Test-Path -LiteralPath $candidate) { throw 'Retained candidate must not be overwritten or remounted.' }
        $case = [ordered]@{ case=$product.case; stage='container-construction'; success=$false; nativeChecks=@{} }
        $report.cases += $case
        if ($product.PSObject.Properties.Name -contains 'preparedVhdName') {
            $preparedVhdMaximumBytes = 134217728
            if ($product.preparedVhdName -cne ('input-' + $product.case + '.vhd') -or
                @($product.patches).Count -ne 0 -or $product.preparedVhdBytes -lt 1 -or
                $product.preparedVhdBytes -gt $preparedVhdMaximumBytes) {
                throw 'Unexpected prepared disposable VHD profile.'
            }
            $prepared = Join-Path $batch.directory $product.preparedVhdName
            $preparedFile = Get-Item -LiteralPath $prepared
            if ($preparedFile.PSIsContainer -or ($preparedFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                $preparedFile.Length -ne $product.preparedVhdBytes -or
                (Get-DiskImage -ImagePath $prepared).Attached -or
                (Get-FileHash -LiteralPath $prepared -Algorithm SHA256).Hash.ToLowerInvariant() -ne $product.expectedVhdSha256) {
                throw 'Prepared detached VHD bytes disagree.'
            }
            [IO.File]::Copy($prepared,$candidate,$false)
        } else {
            [IO.File]::Copy($base,$candidate,$false)
            $file = [IO.FileStream]::new($candidate,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            try {
            $total = 0
            foreach ($patch in $product.patches) {
                $offset = [long]$patch.offset
                $value = [Convert]::FromBase64String($patch.data)
                if ($offset -lt 0 -or $offset % 512 -ne 0 -or $value.Length -eq 0 -or
                    $value.Length % 512 -ne 0 -or $value.Length -gt 1048576 -or
                    $value.Length -ne $patch.bytes -or $offset + $value.Length -gt $file.Length) { throw 'Container patch is outside its reviewed bounds.' }
                $total += $value.Length
                if ($total -gt 1048576) { throw 'Aggregate candidate patches exceed their bound.' }
                [void]$file.Seek($offset,[IO.SeekOrigin]::Begin)
                $file.Write($value,0,$value.Length)
            }
            $file.Flush($true)
            } finally { $file.Dispose() }
        }
        $case.preMountSha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($case.preMountSha256 -ne $product.expectedVhdSha256) { throw 'Candidate differs before native attachment.' }
        $case.mountStartedUtc = [DateTime]::UtcNow.ToString('o')
        $since = [DateTime]::Parse($case.mountStartedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
        $case.stage = 'native-mount'
        # Preserve the first attempted identity even if the runner is interrupted.
        $report | ConvertTo-Json -Depth 16 | Out-File -Encoding utf8 -LiteralPath $reportPath
        $image = Mount-DiskImage -ImagePath $candidate -StorageType VHD -Access ReadWrite -NoDriveLetter -PassThru
        $attached = $true
        $disk = $image | Get-Disk
        if (@($disk).Count -ne 1 -or $protectedDiskNumbers -contains $disk.Number -or $disk.Size -ne $diskBytes -or
            [int]$disk.CimInstanceProperties['BusType'].Value -ne $fileBackedVirtualBusType -or
            $disk.PartitionStyle -ne 'GPT' -or $disk.IsBoot -or $disk.IsSystem -or $disk.IsOffline -or
            $disk.IsReadOnly -or [Guid]$disk.Guid -ne [Guid]$product.diskGuid) { throw 'Candidate virtual disk identity changed.' }
        $partition = Get-Partition -DiskNumber $disk.Number -PartitionNumber $partitionNumber
        if ($partition.DiskNumber -ne $disk.Number -or $partition.Offset -ne $partitionOffset -or $partition.Size -ne $partitionBytes -or
            $partition.IsBoot -or $partition.IsSystem -or [Guid]$partition.Guid -ne [Guid]$product.partitionGuid -or
            [Guid]$partition.GptType -ne [Guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7') { throw 'Candidate partition identity changed.' }
        if (@(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Candidate letter became occupied.' }
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partitionNumber -AccessPath 'R:\'
        Assert-NativeCandidateDrive $disk $partition
        $volume = Get-Volume -DriveLetter R
        $encryption = Get-BitLockerVolume -MountPoint 'R:'
        $case.disk = $disk | Select-Object Number,Guid,UniqueId,BusType,Size,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly
        $case.partition = $partition | Select-Object DiskNumber,PartitionNumber,Guid,GptType,Offset,Size,IsBoot,IsSystem
        $case.volume = $volume | Select-Object UniqueId,DriveLetter,FileSystemType,FileSystemLabel,HealthStatus,Size,SizeRemaining
        $case.encryption = $encryption | Select-Object VolumeStatus,EncryptionMethod,EncryptionPercentage
        if ($volume.FileSystemType -ne 'NTFS' -or $volume.FileSystemLabel -ne $volumeLabel -or
            $volume.HealthStatus -ne 'Healthy' -or $encryption.VolumeStatus -ne 'FullyDecrypted' -or
            $encryption.EncryptionMethod -ne 'None' -or $encryption.EncryptionPercentage -ne 0) { throw 'Candidate is not the expected healthy plaintext NTFS volume.' }
        $case.stage = 'native-files-and-metadata'
        Assert-NativeCandidateDrive $disk $partition
        $case.nativeChecks = Test-NativeFiles $product $product.root $batch.targetAcl $batch.fileId
        Assert-NativeCandidateDrive $disk $partition
        $dirty = @(& "$env:SystemRoot\System32\fsutil.exe" dirty query 'R:' 2>&1)
        $dirtyExit = $LASTEXITCODE
        if ($dirtyExit -ne 0 -or ($dirty -join "`n") -notmatch 'Volume - R: is NOT Dirty') { throw 'Native clean-volume observation failed.' }
        $case.dirtyQuery = [ordered]@{ exitCode=$dirtyExit; output=$dirty }
        Assert-NativeCandidateDrive $disk $partition
        $chkdsk = @(& "$env:SystemRoot\System32\chkdsk.exe" 'R:' 2>&1)
        $chkdskExit = $LASTEXITCODE
        $case.chkdsk = [ordered]@{ exitCode=$chkdskExit; output=$chkdsk }
        if ($chkdskExit -ne 0 -or ($chkdsk -join "`n") -notmatch 'found no problems') { throw 'Read-only native chkdsk failed.' }
        $case.nativeEventAttempts = @()
        $eventsReady = $false
        for ($attempt = 0; $attempt -lt $nativeEventMaximumAttempts; $attempt++) {
            $case.nativeEvents = @()
            [void](Get-NativeEvents $since $volume.UniqueId $product $case)
            $ntfsEvents = $case.nativeEvents[0]
            $case.nativeEventAttempts += [ordered]@{
                queriedUtc=[DateTime]::UtcNow.ToString('o'); observations=$case.nativeEvents
            }
            $eventsReady = @($ntfsEvents.matchingHealthyEvents).Count -gt 0 -and
                @($ntfsEvents.matchingInjectedTornPages).Count -eq @($product.expectedTornLogPages).Count
            if ($eventsReady) { break }
            if ($attempt + 1 -lt $nativeEventMaximumAttempts) {
                Start-Sleep -Milliseconds $nativeEventPollMilliseconds
            }
        }
        if (-not $eventsReady) { throw 'Matching healthy and injected-page events were not observed within the polling bound.' }
        $case.stage = 'ordinary-detach'
        Dismount-DiskImage -ImagePath $candidate
        $attached = $false
        if ((Get-DiskImage -ImagePath $candidate).Attached -or
            @(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Candidate detach not observed.' }
        $case.postDetachSha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        $case.stage = 'complete'
        $case.success = $true
        $report | ConvertTo-Json -Depth 16 | Out-File -Encoding utf8 -LiteralPath $reportPath
    }
    $report.originalAfter = Test-OriginalDisk
    $report.stage = 'complete'
    $report.success = $true
} catch {
    $report.error = $_.Exception.ToString()
    $report.errorRecord = $_.ToString()
} finally {
    if ($attached -and $null -ne $candidate) {
        try { Dismount-DiskImage -ImagePath $candidate; $report.failedCandidateDetached = -not (Get-DiskImage -ImagePath $candidate).Attached }
        catch { $report.detachError = $_.Exception.ToString() }
    }
    if ($null -ne $batch -and $report.Contains('originalBefore') -and
        $report.originalBefore.success -and -not $report.Contains('originalAfter')) {
        try { $report.originalAfter = Test-OriginalDisk }
        catch { $report.originalAfterError = $_.Exception.ToString() }
    }
    $report.finishedUtc = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 16 | Out-File -Encoding utf8 -LiteralPath $reportPath
}
if (-not $report.success) { throw ('Native recovery failed at ' + $report.stage + '; see ' + $reportPath) }
