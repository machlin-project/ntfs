# Pure guard regression: no device discovery, attachment or formatting.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\windows_scratch_guard.ps1')
$path = 'C:\Temp\MachlinNTFSCloud-unit\base.vhd'
$image = [pscustomobject]@{Attached=$true;ImagePath=$path}
$disk = [pscustomobject]@{Number=4;Size=268435456;IsBoot=$false;IsSystem=$false;
    IsOffline=$false;IsReadOnly=$false;BusType=15;UniqueId='unit-id';
    Guid='55b1872c-235f-447e-af3c-32a015c5a7d6';PartitionStyle='GPT'}
$part = [pscustomobject]@{DiskNumber=4;PartitionNumber=2;IsBoot=$false;IsSystem=$false;
    DriveLetter='R';
    Offset=16777216;Size=250609664;Guid='637edc09-bb66-4b70-a3b8-e50393b5dafb';
    GptType='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'}
$checks = 0
foreach ($name in @('scripts\bootstrap_windows_ntfs.ps1','scripts\windows_scratch_guard.ps1',
    'tests\windows_image_recovery.ps1','tests\windows_directory_guard.ps1')) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot) $name),
        [ref]$tokens, [ref]$errors)
    if (@($errors).Count -ne 0) { throw ($name + ': ' + ($errors -join '; ')) }
    $checks++
}
function Refuse([scriptblock]$Action) {
    $refused = $false
    try { & $Action | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'Unsafe identity was accepted.' }
    $script:checks++
}
[void](Assert-ScratchDisk $image $disk $path 268435456 @(0,1,2) $disk $false)
[void](Assert-ScratchPartition $part $disk $part)
foreach ($field in @('IsBoot','IsSystem','IsOffline','IsReadOnly')) {
    $changed = $disk.PSObject.Copy(); $changed.$field = $true
    Refuse { Assert-ScratchDisk $image $changed $path 268435456 @(0,1,2) $disk $false }
}
foreach ($field in @('Number','Size','UniqueId','Guid','PartitionStyle','BusType')) {
    $changed = $disk.PSObject.Copy()
    $changed.$field = @{Number=0;Size=268435457;UniqueId='other';
        Guid='086795c8-b678-48b4-a2b2-22300c5871cb';PartitionStyle='RAW';BusType=17}[$field]
    Refuse { Assert-ScratchDisk $image $changed $path 268435456 @(0,1,2) $disk $false }
}
$changedImage = $image.PSObject.Copy(); $changedImage.Attached = $false
Refuse { Assert-ScratchDisk $changedImage $disk $path 268435456 @(0) $disk $false }
Refuse { Assert-ScratchDisk $image $disk 'C:\other.vhd' 268435456 @(0) $disk $false }
foreach ($field in @('DiskNumber','PartitionNumber','Offset','Size','Guid','GptType','IsBoot','IsSystem')) {
    $changed = $part.PSObject.Copy()
    $changed.$field = @{DiskNumber=0;PartitionNumber=3;Offset=16777728;Size=250610176;
        Guid='086795c8-b678-48b4-a2b2-22300c5871cb';GptType='086795c8-b678-48b4-a2b2-22300c5871cb';
        IsBoot=$true;IsSystem=$true}[$field]
    Refuse { Assert-ScratchPartition $changed $disk $part }
}
$volume = [pscustomobject]@{DriveLetter='R';FileSystemType='NTFS';FileSystemLabel='MachlinCloudNTFS';
    HealthStatus='Healthy';UniqueId='unit-volume'}
[void](Assert-ScratchDrive @($part) $volume $disk $part 'R' $volume)
Refuse { Assert-ScratchDrive @() $volume $disk $part 'R' $volume }
Refuse { Assert-ScratchDrive @($part,$part) $volume $disk $part 'R' $volume }
foreach ($field in @('DiskNumber','PartitionNumber','Guid','DriveLetter','Offset','Size')) {
    $changed = $part.PSObject.Copy()
    $changed.$field = @{DiskNumber=0;PartitionNumber=3;DriveLetter='S';Offset=16777728;Size=250610176;
        Guid='086795c8-b678-48b4-a2b2-22300c5871cb'}[$field]
    Refuse { Assert-ScratchDrive @($changed) $volume $disk $part 'R' $volume }
}
foreach ($field in @('DriveLetter','FileSystemType','FileSystemLabel','HealthStatus','UniqueId')) {
    $changed = $volume.PSObject.Copy(); $changed.$field = 'wrong'
    Refuse { Assert-ScratchDrive @($part) $changed $disk $part 'R' $volume }
}
Write-Output "PASS: $checks fail-closed scratch identity guards; no native disk operations"
