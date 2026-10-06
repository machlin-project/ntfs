# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Read-only native checks of a main-reviewed disposable disk candidate.
param(
    [Parameter(Mandatory=$true)][string] $ExpectedManifest,
    [Parameter(Mandatory=$true)][string] $ReportName
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($ReportName -notmatch '^[A-Za-z0-9-]{1,96}$') {
    throw 'A bounded plain report name is required.'
}
$reportPath = Join-Path $env:SystemRoot ('Temp\' + $ReportName + '.json')
if (Test-Path -LiteralPath $reportPath) {
    throw 'Retained acceptance reports must not be replaced.'
}
$report = [ordered]@{
    schemaVersion = 1
    stage = 'identity-guards'
    success = $false
    startedUtc = [DateTime]::UtcNow.ToString('o')
    checks = @()
    fskitWritesQualified = $false
}
$timeMismatch = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Native disk checks require the authorized administrative guest context.'
    }
    $report.identity = $identity.Name
    $disk = Get-Disk -Number 1
    if ($disk.Size -ne 8589934592 -or $disk.PartitionStyle -ne 'GPT' -or
        $disk.IsBoot -or $disk.IsSystem -or $disk.IsOffline -or $disk.IsReadOnly -or
        $disk.SerialNumber -ne '29494EE0-8857-4968-8_00000001.' -or
        $disk.UniqueId -ne '1B36QEMU NVMe Ctrl                          000129494EE0-8857-4968-8') {
        throw 'The disposable test disk identity changed.'
    }
    $partition = Get-Partition -DriveLetter T
    $volume = Get-Volume -DriveLetter T
    $encryption = Get-BitLockerVolume -MountPoint 'T:'
    if ($partition.DiskNumber -ne 1 -or $partition.PartitionNumber -ne 2 -or
        $partition.Offset -ne 16777216 -or $partition.Size -ne 8572108800 -or
        $partition.IsBoot -or $partition.IsSystem -or
        $partition.GptType -ne '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -or
        $volume.FileSystemType -ne 'NTFS' -or $volume.FileSystemLabel -ne 'MachlinNTFS' -or
        $encryption.VolumeStatus -ne 'FullyDecrypted' -or
        $encryption.EncryptionPercentage -ne 0 -or $encryption.EncryptionMethod -ne 'None') {
        throw 'The expected plaintext NTFS test partition is unavailable.'
    }
    $report.disk = $disk | Select-Object Number,FriendlyName,SerialNumber,UniqueId,
        BusType,Size,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly
    $report.partition = $partition | Select-Object DiskNumber,PartitionNumber,
        DriveLetter,Offset,Size,GptType,Guid,IsBoot,IsSystem
    $report.volume = $volume | Select-Object DriveLetter,FileSystemType,
        FileSystemLabel,AllocationUnitSize,Size,SizeRemaining,HealthStatus
    $report.encryption = $encryption | Select-Object MountPoint,VolumeStatus,
        EncryptionPercentage,EncryptionMethod,ProtectionStatus
    $report.os = Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime
    $expected = Get-Content -LiteralPath $ExpectedManifest -Raw | ConvertFrom-Json
    if ($expected.root -ne 'T:\MachlinWriteCases-native-write-alias-20261006' -or
        @($expected.files).Count -ne 4) {
        throw 'The manifest does not identify this reviewed workload.'
    }
    $report.stage = 'exact-file-and-stream-checks'
    foreach ($entry in $expected.files) {
        if ($entry.relativePath -notmatch '^(initialized\.bin|rename-after\.txt|resident\.txt|child\\nested\.txt)$' -or
            $entry.sha256 -notmatch '^[a-f0-9]{64}$') {
            throw 'An expected file is outside the reviewed workload.'
        }
        $path = Join-Path $expected.root $entry.relativePath
        $file = Get-Item -LiteralPath $path
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $passed = $file.Length -eq $entry.bytes -and $hash -eq $entry.sha256
        $report.checks += [ordered]@{ relativePath=$entry.relativePath; bytes=$file.Length;
            sha256=$hash; expectedSha256=$entry.sha256; passed=$passed }
        if (-not $passed) {
            throw ('Native file bytes disagree: ' + $entry.relativePath)
        }
        if ($entry.PSObject.Properties.Name -contains 'lastWriteFileTime') {
            if ($entry.lastWriteFileTime -notmatch '^[0-9]{1,19}$') {
                throw 'A bounded native file-time observation is required.'
            }
            $actualTime = $file.LastWriteTimeUtc.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
            $report.lastWriteTime = [ordered]@{ relativePath=$entry.relativePath;
                fileTime=$actualTime; expectedFileTime=$entry.lastWriteFileTime;
                passed=($actualTime -eq $entry.lastWriteFileTime) }
            if (-not $report.lastWriteTime.passed) {
                $timeMismatch = $true
            }
        }
    }
    $stream = $expected.namedStream
    if ($stream.relativePath -ne 'resident.txt' -or $stream.name -ne 'original-stream' -or
        $stream.bytes -ne 29 -or $stream.sha256 -notmatch '^[a-f0-9]{64}$') {
        throw 'The named-stream manifest is outside the reviewed workload.'
    }
    $streamBytes = [byte[]](Get-Content -LiteralPath (Join-Path $expected.root $stream.relativePath) -Stream $stream.name -Encoding Byte -ReadCount 0)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $streamHash = [BitConverter]::ToString($algorithm.ComputeHash($streamBytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
    $report.namedStream = [ordered]@{ name=$stream.name; bytes=$streamBytes.Length;
        sha256=$streamHash; expectedSha256=$stream.sha256;
        passed=($streamBytes.Length -eq $stream.bytes -and $streamHash -eq $stream.sha256) }
    if (-not $report.namedStream.passed) {
        throw 'Native alternate-stream bytes disagree.'
    }
    $report.stage = 'native-metadata-observation'
    $target = Join-Path $expected.root 'initialized.bin'
    $report.targetAcl = (Get-Acl -LiteralPath $target).Sddl
    $fileId = & (Join-Path $env:SystemRoot 'System32\fsutil.exe') file queryfileid $target 2>&1
    $report.fileId = [ordered]@{ exitCode=$LASTEXITCODE; output=@($fileId | ForEach-Object { "$_" }) }
    if ($report.fileId.exitCode -ne 0) {
        throw 'Native file-identity observation failed.'
    }
    $report.stage = 'independent-readonly-chkdsk'
    $chkdsk = & (Join-Path $env:SystemRoot 'System32\chkdsk.exe') 'T:' 2>&1
    $report.chkdsk = [ordered]@{ exitCode=$LASTEXITCODE; output=@($chkdsk | ForEach-Object { "$_" }) }
    if ($report.chkdsk.exitCode -ne 0) {
        throw 'Read-only native chkdsk did not pass.'
    }
    if ($timeMismatch) {
        throw 'Native journal recovery did not publish the expected file time.'
    }
    $report.stage = 'complete'
    $report.success = $true
} catch {
    $report.error = $_.Exception.ToString()
} finally {
    $report.completedUtc = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $reportPath -Encoding utf8
}
