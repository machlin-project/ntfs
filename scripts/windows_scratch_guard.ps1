# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Pure admission predicates. Discovery and mutations belong to the caller.
function Assert-ScratchDisk($Image, $Disk, [string]$Path, [long]$Bytes,
                            [int[]]$ProtectedNumbers, $Expected, [bool]$ReadOnly) {
    # MSFT_Disk.BusType 15 is File Backed Virtual. Read the raw CIM value,
    # rather than relying on localized/generated enum display spelling.
    $fileBackedVirtualBusType = 15
    $busType = -1
    if ($null -ne $Disk) {
        $busType = if ($Disk.GetType().FullName -ceq 'Microsoft.Management.Infrastructure.CimInstance') {
            [int]$Disk.CimInstanceProperties['BusType'].Value
        } else { [int]$Disk.BusType }
    }
    if ($null -eq $Image -or $null -eq $Disk -or -not $Image.Attached -or
        -not [string]::Equals($Image.ImagePath, $Path, [StringComparison]::OrdinalIgnoreCase) -or
        $Disk.Number -lt 0 -or $ProtectedNumbers -contains [int]$Disk.Number -or
        $Disk.Size -ne $Bytes -or $Disk.IsBoot -or $Disk.IsSystem -or $Disk.IsOffline -or
        $Disk.IsReadOnly -ne $ReadOnly -or $busType -ne $fileBackedVirtualBusType -or
        [string]::IsNullOrWhiteSpace($Disk.UniqueId)) {
        throw 'Scratch VHD is not the exact attached non-host, nonboot, nonsystem disk.'
    }
    if ($null -ne $Expected -and ($Disk.UniqueId -cne $Expected.UniqueId -or
        $Disk.PartitionStyle.ToString() -ne 'GPT' -or [Guid]$Disk.Guid -ne [Guid]$Expected.Guid)) {
        throw 'Scratch disk identity changed.'
    }
    return $Disk
}

function Assert-ScratchPartition($Partition, $Disk, $Expected) {
    $basicData = [Guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
    if ($null -eq $Partition -or $Partition.DiskNumber -ne $Disk.Number -or
        $Partition.IsBoot -or $Partition.IsSystem -or $Partition.Offset -lt 1048576 -or
        $Partition.Size -le 0 -or $Partition.Offset -ge $Disk.Size -or
        $Partition.Size -gt $Disk.Size - $Partition.Offset -or
        $Partition.Offset % 512 -ne 0 -or $Partition.Size % 512 -ne 0 -or
        [Guid]$Partition.GptType -ne $basicData -or [Guid]$Partition.Guid -eq [Guid]::Empty) {
        throw 'Scratch partition does not belong to the admitted test disk.'
    }
    if ($null -ne $Expected -and ($Partition.PartitionNumber -ne $Expected.PartitionNumber -or
        [Guid]$Partition.Guid -ne [Guid]$Expected.Guid -or
        $Partition.Offset -ne $Expected.Offset -or $Partition.Size -ne $Expected.Size)) {
        throw 'Scratch partition identity or geometry changed.'
    }
    return $Partition
}

function Assert-ScratchDrive($Partitions, $Volume, $Disk, $ExpectedPartition,
                            [string]$Letter, $ExpectedVolume) {
    $routes = @($Partitions)
    if ($routes.Count -ne 1 -or $null -eq $Volume -or
        $routes[0].DriveLetter.ToString() -cne $Letter -or
        $Volume.DriveLetter.ToString() -cne $Letter -or
        $Volume.FileSystemType.ToString() -cne 'NTFS' -or
        $Volume.FileSystemLabel -cne 'MachlinCloudNTFS' -or
        $Volume.HealthStatus.ToString() -cne 'Healthy' -or
        [string]::IsNullOrWhiteSpace($Volume.UniqueId)) {
        throw 'Scratch drive letter does not uniquely name the expected native volume.'
    }
    [void](Assert-ScratchPartition $routes[0] $Disk $ExpectedPartition)
    if ($null -ne $ExpectedVolume -and $Volume.UniqueId -cne $ExpectedVolume.UniqueId) {
        throw 'Scratch drive-letter volume identity changed.'
    }
    return $Volume
}
