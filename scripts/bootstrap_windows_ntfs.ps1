# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Fresh native NTFS inputs, never an existing disk or owner-machine fixture.
param(
    [Parameter(Mandatory=$true)][string]$Output,
    [ValidatePattern('^[R-Z]$')][string]$DriveLetter = 'R',
    [ValidateRange(128,4096)][int]$SizeMiB = 256,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows_scratch_guard.ps1')
$bytes = [long]$SizeMiB * 1048576
$outputPath = [IO.Path]::GetFullPath($Output)
$tempRoots = @($env:TEMP)
if ($env:RUNNER_TEMP) { $tempRoots += $env:RUNNER_TEMP }
$insideTemp = $false
foreach ($temp in $tempRoots) {
    $tempPath = [IO.Path]::GetFullPath($temp).TrimEnd('\') + '\'
    if ($outputPath.StartsWith($tempPath, [StringComparison]::OrdinalIgnoreCase)) { $insideTemp = $true }
}
if ($outputPath -notmatch '^[A-Za-z]:\\[^"\r\n]+\\MachlinNTFSCloud-[A-Za-z0-9-]{1,64}$' -or
    -not $insideTemp -or
    (Test-Path -LiteralPath $outputPath)) {
    throw 'Use a new MachlinNTFSCloud-<unique tag> directory beneath this process TEMP.'
}
$parent = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($outputPath))
while ($null -ne $parent) {
    if (-not $parent.Exists -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Every output ancestor must be an existing plain directory.'
    }
    $parent = $parent.Parent
}
[void][IO.Directory]::CreateDirectory($outputPath)
$reportPath = Join-Path $outputPath 'bootstrap.json'
$vhd = Join-Path $outputPath 'base.vhd'
$rootName = 'MachlinCloudNTFS-' + [Guid]::NewGuid().ToString('N')
$root = $DriveLetter + ':\' + $rootName
$diskIdentity = $null
$partitionIdentity = $null
$volumeIdentity = $null
$attached = $false
$protectedNumbers = @()
$report = [ordered]@{schema_version=1;provenance='Windows native scratch VHD bootstrap';
    acquisition_status='running';stage='capability';started_utc=[DateTime]::UtcNow.ToString('o');
    automatic_retry=$false;native_recovery_qualified=$false;root_name=$rootName;disk_bytes=$bytes;
    platform=[ordered]@{system='Windows';version=[Environment]::OSVersion.Version.ToString();
        powershell=$PSVersionTable.PSVersion.ToString()};errors=@();commands=@()}
$report.sources = @('bootstrap_windows_ntfs.ps1','windows_scratch_guard.ps1','collect_windows_corpus.py') | ForEach-Object {
    [ordered]@{file=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $_) -Algorithm SHA256).Hash.ToLowerInvariant()}
}
function Save-Report {
    [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
}
function Scratch-Disk([bool]$ReadOnly) {
    $image = Get-DiskImage -ImagePath $vhd
    $disks = @($image | Get-Disk)
    if ($disks.Count -ne 1) { throw 'The VHD must resolve to exactly one disk.' }
    return (Assert-ScratchDisk $image $disks[0] $vhd $bytes $protectedNumbers $diskIdentity $ReadOnly)
}
function Scratch-Partition([bool]$ReadOnly) {
    $disk = Scratch-Disk $ReadOnly
    $partitions = @(Get-Partition -DiskNumber $disk.Number |
        Where-Object { [Guid]$_.GptType -eq [Guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' })
    if ($partitions.Count -ne 1) { throw 'Exactly one scratch basic-data partition is required.' }
    return (Assert-ScratchPartition $partitions[0] $disk $partitionIdentity)
}
function Scratch-Drive([bool]$ReadOnly) {
    $disk = Scratch-Disk $ReadOnly
    $partition = Scratch-Partition $ReadOnly
    $routes = @(Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop)
    $volume = Get-Volume -DriveLetter $DriveLetter
    return (Assert-ScratchDrive $routes $volume $disk $partition $DriveLetter $volumeIdentity)
}
function Flush-File([string]$Path, [byte[]]$Value) {
    [void](Scratch-Drive $false)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Value, 0, $Value.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Run-Native([string]$Name, [string]$Executable, [string[]]$Arguments) {
    # Windows native argv quoting includes doubled trailing backslashes.
    $quoted = @($Arguments | ForEach-Object {
        '"' + ([regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1')) + '"'
    })
    $stdout = Join-Path $outputPath ($Name + '.stdout')
    $stderr = Join-Path $outputPath ($Name + '.stderr')
    $process = Start-Process -FilePath $Executable -ArgumentList ($quoted -join ' ') -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $processHandle = $process.Handle
    if (-not $process.WaitForExit(120000)) {
        $process.Kill(); $process.WaitForExit()
        throw ($Name + ' exceeded its 120-second deadline; preserve outputs and do not retry.')
    }
    $process.Refresh()
    $code = $process.ExitCode
    if ((Get-Item -LiteralPath $stdout).Length + (Get-Item -LiteralPath $stderr).Length -gt 8388608) {
        throw ($Name + ' exceeded its retained diagnostic bound.')
    }
    $lines = @([IO.File]::ReadAllLines($stdout)) + @([IO.File]::ReadAllLines($stderr))
    $report.commands += [ordered]@{name=$Name;exit_code=$code;output=$lines}
    Save-Report
    if ($code -ne 0) { throw ($Name + ' failed; original output retained.') }
    return $lines
}
Save-Report
try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Scratch VHD creation requires an administrative Windows runner token.'
    }
    foreach ($command in @('Get-Disk','Get-DiskImage','Mount-DiskImage','Dismount-DiskImage',
        'Initialize-Disk','New-Partition','Format-Volume','Add-PartitionAccessPath')) {
        [void](Get-Command $command -ErrorAction Stop)
    }
    $protectedNumbers = @((Get-Disk).Number)
    $report.protected_disk_numbers = $protectedNumbers
    if (@(Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue).Count -ne 0 -or
        (Test-Path -LiteralPath ($DriveLetter + ':\'))) { throw 'Scratch drive letter is occupied.' }
    if ((Get-PSDrive -Name $outputPath.Substring(0,1)).Free -lt $bytes * 3 + 1073741824) {
        throw 'Insufficient scratch space for exact retained inputs.'
    }
    $report.stage = 'create-new-vhd'; Save-Report
    # DiskPart is part of Windows and needs no Hyper-V feature installation.
    # Its only instruction creates this absent file; it never selects a disk.
    $diskpartScript = Join-Path $outputPath 'create-vhd.txt'
    [IO.File]::WriteAllText($diskpartScript, "create vdisk file=`"$vhd`" maximum=$SizeMiB type=expandable`r`nexit`r`n")
    [void](Run-Native 'create-vhd' (Join-Path $env:SystemRoot 'System32\diskpart.exe') @('/s',$diskpartScript))
    $file = Get-Item -LiteralPath $vhd
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $file.Length -le 0 -or (Get-DiskImage -ImagePath $vhd).Attached) { throw 'New VHD identity is invalid.' }
    Mount-DiskImage -ImagePath $vhd -StorageType VHD -Access ReadWrite -NoDriveLetter | Out-Null
    $attached = $true
    $disk = Scratch-Disk $false
    if ($disk.PartitionStyle.ToString() -ne 'RAW' -or
        @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Only the newly created empty RAW VHD may be initialized.'
    }
    $report.stage = 'initialize-new-vhd'; Save-Report
    Initialize-Disk -Number (Scratch-Disk $false).Number -PartitionStyle GPT | Out-Null
    $disk = Scratch-Disk $false
    $diskIdentity = $disk | Select-Object UniqueId,Guid
    $report.disk = $disk | Select-Object Number,UniqueId,Guid,Size,LogicalSectorSize,PhysicalSectorSize,BusType,IsBoot,IsSystem
    if ($disk.LogicalSectorSize -ne 512) { throw 'This input profile requires observed 512-byte logical sectors.' }
    $partition = New-Partition -DiskNumber (Scratch-Disk $false).Number -UseMaximumSize
    $partitionIdentity = Assert-ScratchPartition $partition (Scratch-Disk $false) $null
    [void](Scratch-Partition $false)
    $partition | Format-Volume -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel 'MachlinCloudNTFS' -Confirm:$false | Out-Null
    $partition = Scratch-Partition $false
    Add-PartitionAccessPath -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -AccessPath ($DriveLetter + ':\')
    $report.partition = $partition | Select-Object PartitionNumber,Guid,GptType,Offset,Size,IsBoot,IsSystem
    $volume = Scratch-Drive $false
    $volumeIdentity = $volume | Select-Object UniqueId
    $report.volume = $volume | Select-Object UniqueId,FileSystemType,FileSystemLabel,HealthStatus
    $report.stage = 'author-native-namespace'; Save-Report
    [void](Scratch-Drive $false)
    [void][IO.Directory]::CreateDirectory($root)
    Flush-File (Join-Path $root 'resident.txt') ([Text.Encoding]::UTF8.GetBytes("Machlin original resident NTFS write witness.`r`n"))
    $data = New-Object byte[] 1048576
    for ($index=0; $index -lt $data.Length; $index++) { $data[$index] = [byte](($index * 17 + 3) % 256) }
    Flush-File (Join-Path $root 'initialized.bin') $data
    Flush-File (Join-Path $root 'rename-before.txt') ([Text.Encoding]::UTF8.GetBytes('original rename witness'))
    [void](Scratch-Drive $false)
    [IO.File]::Move((Join-Path $root 'rename-before.txt'), (Join-Path $root 'rename-after.txt'))
    [void](Scratch-Drive $false)
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'child'))
    Flush-File (Join-Path $root 'child\nested.txt') ([Text.Encoding]::UTF8.GetBytes('original directory witness'))
    Flush-File ((Join-Path $root 'resident.txt') + ':original-stream') ([Text.Encoding]::ASCII.GetBytes('original named stream witness'))
    [void](Scratch-Drive $false)
    $targetId = @(Run-Native 'initialized-file-id' (Join-Path $env:SystemRoot 'System32\fsutil.exe') @('file','queryfileid',(Join-Path $root 'initialized.bin')))
    [void](Scratch-Drive $false)
    $residentId = @(Run-Native 'resident-file-id' (Join-Path $env:SystemRoot 'System32\fsutil.exe') @('file','queryfileid',(Join-Path $root 'resident.txt')))
    [void](Scratch-Drive $false)
    $report.native_files = [ordered]@{target_acl=(Get-Acl -LiteralPath (Join-Path $root 'initialized.bin')).Sddl;
        file_id=[ordered]@{exitCode=0;output=$targetId};
        resident_acl=(Get-Acl -LiteralPath (Join-Path $root 'resident.txt')).Sddl;
        resident_file_id=[ordered]@{exitCode=0;output=$residentId}}
    $report.stage = 'native-readonly-check'; Save-Report
    [void](Scratch-Drive $false)
    [void](Run-Native 'read-only-chkdsk' (Join-Path $env:SystemRoot 'System32\chkdsk.exe') @($DriveLetter + ':'))
    $report.stage = 'lock-and-flush-volume'; Save-Report
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class MachlinCloudVolumeFlush {
    const uint GenericReadWrite = 0xc0000000;
    const uint ShareReadWrite = 3;
    const uint OpenExisting = 3;
    const uint LockVolume = 0x00090018;
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input,
        uint inputBytes, IntPtr output, uint outputBytes, out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool FlushFileBuffers(SafeFileHandle handle);
    public static void Flush(string name) {
        using (SafeFileHandle handle = CreateFileW(name, GenericReadWrite, ShareReadWrite,
                IntPtr.Zero, OpenExisting, 0, IntPtr.Zero)) {
            if (handle.IsInvalid) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            uint returned;
            if (!DeviceIoControl(handle, LockVolume, IntPtr.Zero, 0, IntPtr.Zero, 0,
                    out returned, IntPtr.Zero) || !FlushFileBuffers(handle)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
'@
    [void](Scratch-Drive $false)
    [MachlinCloudVolumeFlush]::Flush('\\.\' + $DriveLetter + ':')
    $report.volume_lock_and_flush_succeeded = $true
    $report.stage = 'ordinary-detach'; Save-Report
    [void](Scratch-Partition $false)
    Dismount-DiskImage -ImagePath $vhd
    $attached = $false
    if ((Get-DiskImage -ImagePath $vhd).Attached) { throw 'Writable VHD detach was not observed.' }
    $frozenHash = (Get-FileHash -LiteralPath $vhd -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.stage = 'readonly-native-corpus'; Save-Report
    Mount-DiskImage -ImagePath $vhd -StorageType VHD -Access ReadOnly -NoDriveLetter | Out-Null
    $attached = $true
    $partition = Scratch-Partition $true
    Add-PartitionAccessPath -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -AccessPath ($DriveLetter + ':\')
    [void](Scratch-Drive $true)
    [void](Run-Native 'collect-readonly-corpus' $Python @((Join-Path $PSScriptRoot 'collect_windows_corpus.py'),
        '--volume',($DriveLetter + ':\'),'--tree',$rootName,'--output',(Join-Path $outputPath 'corpus'),
        '--max-image-bytes',"$bytes",'--max-entries','32'))
    [void](Scratch-Drive $true)
    Dismount-DiskImage -ImagePath $vhd
    $attached = $false
    if ((Get-DiskImage -ImagePath $vhd).Attached -or
        (Get-FileHash -LiteralPath $vhd -Algorithm SHA256).Hash.ToLowerInvariant() -cne $frozenHash) {
        throw 'Read-only acquisition changed the detached VHD.'
    }
    $report.vhd = [ordered]@{file='base.vhd';bytes=(Get-Item -LiteralPath $vhd).Length;sha256=$frozenHash;detached=$true}
    $corpusPath = Join-Path $outputPath 'corpus\manifest.json'
    $report.corpus = [ordered]@{file='corpus/manifest.json';sha256=(Get-FileHash -LiteralPath $corpusPath -Algorithm SHA256).Hash.ToLowerInvariant()}
    $report.acquisition_status = 'complete'; $report.stage = 'complete'
} catch {
    $report.acquisition_status = 'failed'
    $report.errors += $_.Exception.ToString()
} finally {
    if ($attached) {
        try {
            # Detach by the created file identity only; never guess a disk number.
            Dismount-DiskImage -ImagePath $vhd
            $report.failed_candidate_detached = -not (Get-DiskImage -ImagePath $vhd).Attached
        } catch { $report.errors += $_.Exception.ToString() }
    }
    $report.completed_utc = [DateTime]::UtcNow.ToString('o'); Save-Report
}
if ($report.acquisition_status -ne 'complete') { throw ('Native bootstrap failed at ' + $report.stage + '; see ' + $reportPath) }
Write-Output $reportPath
