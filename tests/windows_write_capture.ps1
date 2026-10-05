# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Run only in the dedicated Windows VM. The blank test disk is independently
# reviewed before -InitializeBlankDisk is selected. No system volume is admitted.
param(
    [switch] $InitializeBlankDisk,
    [ValidatePattern('^[a-z0-9-]{1,48}$')]
    [string] $CaptureName = 'native-write-baseline'
)

$ErrorActionPreference = 'Stop'
$TestDiskNumber = 1
$TestDiskBytes = [uint64]8589934592
$TestDriveLetter = 'T'
$TestVolumeLabel = 'MachlinNTFS'
$ClusterBytes = 4096
$GuestOutput = Join-Path $env:SystemRoot 'Temp'
$ReportPath = Join-Path $GuestOutput ($CaptureName + '.json')
$ImagePath = Join-Path $GuestOutput ($CaptureName + '.raw.gz')
if ((Test-Path -LiteralPath $ReportPath) -or (Test-Path -LiteralPath $ImagePath)) {
    throw 'Capture outputs already exist; use a fresh capture name.'
}
$report = [ordered]@{
    schema = 1
    captureName = $CaptureName
    startedUtc = [DateTime]::UtcNow.ToString('o')
    success = $false
    stage = 'admission'
    writesImplemented = $false
    recoveryQualified = $false
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The capture requires a genuine administrative guest token.'
    }
    $disk = Get-Disk -Number $TestDiskNumber
    if ($disk.Size -ne $TestDiskBytes -or $disk.IsBoot -or $disk.IsSystem -or
        $disk.IsOffline -or $disk.IsReadOnly -or $disk.BusType -ne 'NVMe' -or
        $disk.FriendlyName -ne 'QEMU NVMe Ctrl') {
        throw 'The reviewed isolated disk identity does not match.'
    }
    $report.diskBefore = $disk | Select-Object Number,FriendlyName,SerialNumber,
        UniqueId,BusType,Size,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly
    if ($InitializeBlankDisk) {
        if ($disk.PartitionStyle -ne 'RAW' -or
            @(Get-Partition -DiskNumber $TestDiskNumber -ErrorAction SilentlyContinue).Count -ne 0 -or
            @(Get-Volume -DriveLetter $TestDriveLetter -ErrorAction SilentlyContinue).Count -ne 0) {
            throw 'Initialization requires the reviewed blank disk and unused test letter.'
        }
        $report.stage = 'initialize-isolated-disk'
        Initialize-Disk -Number $TestDiskNumber -PartitionStyle GPT | Out-Null
        $partition = New-Partition -DiskNumber $TestDiskNumber -UseMaximumSize -DriveLetter $TestDriveLetter
        $partition | Format-Volume -FileSystem NTFS -AllocationUnitSize $ClusterBytes -NewFileSystemLabel $TestVolumeLabel -Confirm:$false | Out-Null
    }
    $partition = Get-Partition -DriveLetter $TestDriveLetter
    $volume = Get-Volume -DriveLetter $TestDriveLetter
    if ($partition.DiskNumber -ne $TestDiskNumber -or $partition.IsBoot -or
        $partition.IsSystem -or $volume.FileSystemType -ne 'NTFS' -or
        $volume.FileSystemLabel -ne $TestVolumeLabel -or
        @(Get-Partition -DiskNumber $TestDiskNumber | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne $TestDriveLetter }).Count -ne 0) {
        throw 'The test partition/volume binding does not match.'
    }
    $report.partition = $partition | Select-Object DiskNumber,PartitionNumber,
        DriveLetter,Offset,Size,GptType,IsBoot,IsSystem
    $report.volume = $volume | Select-Object DriveLetter,FileSystemType,
        FileSystemLabel,Size,SizeRemaining,HealthStatus
    $encryption = Get-BitLockerVolume -MountPoint ($TestDriveLetter + ':')
    $report.encryption = $encryption | Select-Object MountPoint,VolumeType,
        VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod,LockStatus
    if ($encryption.VolumeStatus.ToString() -ne 'FullyDecrypted' -or
        $encryption.EncryptionMethod.ToString() -ne 'None') {
        throw 'Native NTFS capture requires the isolated test volume to be fully decrypted.'
    }
    $report.os = Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption,Version,BuildNumber,OSArchitecture
    $report.stage = 'original-native-workload'
    $root = $TestDriveLetter + ':\MachlinWriteCases-' + $CaptureName
    if (Test-Path -LiteralPath $root) {
        throw 'The original baseline workload must not overwrite an earlier workload.'
    }
    New-Item -ItemType Directory -Path $root | Out-Null
    $resident = [Text.Encoding]::UTF8.GetBytes("Machlin original resident NTFS write witness.`r`n")
    [IO.File]::WriteAllBytes((Join-Path $root 'resident.txt'), $resident)
    $dataBytes = 1024 * 1024
    $data = New-Object byte[] $dataBytes
    for ($index = 0; $index -lt $data.Length; $index++) {
        $data[$index] = [byte](($index * 17 + 3) % 256)
    }
    [IO.File]::WriteAllBytes((Join-Path $root 'initialized.bin'), $data)
    $patchOffset = $ClusterBytes - 99
    $patch = [Text.Encoding]::UTF8.GetBytes(('Native-Windows-existing-range.' * 37))
    $stream = [IO.File]::Open((Join-Path $root 'initialized.bin'), [IO.FileMode]::Open,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Position = $patchOffset
        $stream.Write($patch, 0, $patch.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    [IO.File]::WriteAllText((Join-Path $root 'rename-before.txt'), 'original rename witness')
    Move-Item -LiteralPath (Join-Path $root 'rename-before.txt') -Destination (Join-Path $root 'rename-after.txt')
    [IO.File]::WriteAllText((Join-Path $root 'deleted.txt'), 'original delete witness')
    Remove-Item -LiteralPath (Join-Path $root 'deleted.txt')
    New-Item -ItemType Directory -Path (Join-Path $root 'child') | Out-Null
    [IO.File]::WriteAllText((Join-Path $root 'child\nested.txt'), 'original directory witness')
    $streamText = 'original named stream witness'
    Set-Content -LiteralPath (Join-Path $root 'resident.txt') -Stream 'original-stream' -Value $streamText -Encoding Ascii -NoNewline
    $streamBytes = [byte[]](Get-Content -LiteralPath (Join-Path $root 'resident.txt') -Stream 'original-stream' -Encoding Byte -ReadCount 0)
    $streamHash = [Security.Cryptography.SHA256]::Create()
    try {
        $streamDigest = [BitConverter]::ToString($streamHash.ComputeHash($streamBytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $streamHash.Dispose()
    }
    $report.workload = [ordered]@{
        root = $root
        initializedBytes = $dataBytes
        patchOffset = $patchOffset
        patchBytes = $patch.Length
        namedStream = [ordered]@{
            relativePath = 'resident.txt'
            name = 'original-stream'
            bytes = $streamBytes.Length
            sha256 = $streamDigest
        }
        files = @(Get-ChildItem -LiteralPath $root -File -Recurse | ForEach-Object {
            [ordered]@{
                relativePath = $_.FullName.Substring($root.Length + 1)
                bytes = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        })
    }
    $report.stage = 'independent-readonly-chkdsk'
    $chkdskOutput = & (Join-Path $env:SystemRoot 'System32\chkdsk.exe') ($TestDriveLetter + ':') 2>&1
    $report.chkdsk = [ordered]@{ exitCode = $LASTEXITCODE; output = @($chkdskOutput | ForEach-Object { "$_" }) }
    if ($LASTEXITCODE -ne 0) {
        throw 'The original Windows baseline must pass independent read-only chkdsk.'
    }
    $report.stage = 'locked-flushed-raw-capture'
    $nativeSource = @'
using System;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

public sealed class MachlinCaptureResult {
    public bool VolumeLockHeld;
    public bool VolumeFlushSucceeded;
    public bool VolumeDismountSucceeded;
    public bool PhysicalFlushSucceeded;
    public long CapturedBytes;
    public string Sha256;
    public string LockedUtc;
    public string CompletedUtc;
    public string RawBootOem;
}

public static class MachlinNativeCapture {
    const uint GenericRead = 0x80000000;
    const uint GenericWrite = 0x40000000;
    const uint ShareReadWrite = 3;
    const uint OpenExisting = 3;
    const uint FsctlLockVolume = 0x00090018;
    const uint FsctlDismountVolume = 0x00090020;
    const int CaptureBufferBytes = 1024 * 1024;
    const int BootJumpBytes = 3;
    const int BootOemBytes = 8;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DeviceIoControl(SafeFileHandle handle, uint code,
        IntPtr input, uint inputBytes, IntPtr output, uint outputBytes,
        out uint returnedBytes, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool FlushFileBuffers(SafeFileHandle handle);

    static SafeFileHandle OpenDevice(string name) {
        SafeFileHandle handle = CreateFileW(name, GenericRead | GenericWrite,
            ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open " + name);
        }
        return handle;
    }
    static void Control(SafeFileHandle handle, uint code, string description) {
        uint returned;
        if (!DeviceIoControl(handle, code, IntPtr.Zero, 0, IntPtr.Zero, 0,
                out returned, IntPtr.Zero)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), description);
        }
    }
    static void Persist(SafeFileHandle handle, string description) {
        if (!FlushFileBuffers(handle)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), description);
        }
    }
    public static MachlinCaptureResult Capture(string volumeName, string diskName,
            long diskBytes, long partitionOffset, string outputPath) {
        MachlinCaptureResult result = new MachlinCaptureResult();
        // The same volume handle owns the successful lock until every raw byte
        // and the compressed output have been consumed and persisted.
        using (SafeFileHandle volume = OpenDevice(volumeName)) {
            Control(volume, FsctlLockVolume, "FSCTL_LOCK_VOLUME");
            result.VolumeLockHeld = true;
            result.LockedUtc = DateTime.UtcNow.ToString("o");
            Persist(volume, "FlushFileBuffers locked volume");
            result.VolumeFlushSucceeded = true;
            Control(volume, FsctlDismountVolume, "FSCTL_DISMOUNT_VOLUME while locked");
            result.VolumeDismountSucceeded = true;
            using (SafeFileHandle disk = OpenDevice(diskName)) {
                Persist(disk, "FlushFileBuffers physical test device");
                result.PhysicalFlushSucceeded = true;
                using (FileStream input = new FileStream(disk, FileAccess.Read, CaptureBufferBytes))
                using (FileStream output = new FileStream(outputPath, FileMode.CreateNew,
                        FileAccess.Write, FileShare.None, CaptureBufferBytes))
                using (SHA256 hash = SHA256.Create()) {
                    byte[] bootPrefix = new byte[BootJumpBytes + BootOemBytes];
                    input.Position = partitionOffset;
                    int prefixBytes = input.Read(bootPrefix, 0, bootPrefix.Length);
                    if (prefixBytes != bootPrefix.Length) {
                        throw new EndOfStreamException("Short physical test volume boot prefix");
                    }
                    result.RawBootOem = System.Text.Encoding.ASCII.GetString(bootPrefix,
                        BootJumpBytes, BootOemBytes);
                    if (result.RawBootOem != "NTFS    ") {
                        throw new InvalidDataException("The locked physical test volume is not plaintext NTFS");
                    }
                    input.Position = 0;
                    using (GZipStream compressed = new GZipStream(output, CompressionLevel.Fastest, true)) {
                        byte[] bytes = new byte[CaptureBufferBytes];
                        long remaining = diskBytes;
                        while (remaining != 0) {
                            int requested = (int)Math.Min(remaining, bytes.Length);
                            int count = input.Read(bytes, 0, requested);
                            if (count == 0) {
                                throw new EndOfStreamException("Short physical test disk capture");
                            }
                            hash.TransformBlock(bytes, 0, count, bytes, 0);
                            compressed.Write(bytes, 0, count);
                            remaining -= count;
                            result.CapturedBytes += count;
                        }
                        hash.TransformFinalBlock(new byte[0], 0, 0);
                        result.Sha256 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
                    }
                    output.Flush(true);
                }
            }
            result.CompletedUtc = DateTime.UtcNow.ToString("o");
        }
        return result;
    }
}
'@
    Add-Type -TypeDefinition $nativeSource -ReferencedAssemblies 'System.dll','System.IO.Compression.dll'
    $report.capture = [MachlinNativeCapture]::Capture('\\.\T:', '\\.\PhysicalDrive1',
        [long]$TestDiskBytes, [long]$partition.Offset, $ImagePath)
    $report.image = [ordered]@{
        guestPath = $ImagePath
        compressedBytes = (Get-Item -LiteralPath $ImagePath).Length
        compressedSha256 = (Get-FileHash -LiteralPath $ImagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        encoding = 'gzip-raw-whole-isolated-disk'
    }
    $report.stage = 'complete'
    $report.success = $true
} catch {
    $report.error = $_.Exception.ToString()
} finally {
    $report.completedUtc = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $ReportPath -Encoding utf8
}
