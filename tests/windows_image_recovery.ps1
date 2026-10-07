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
if ($ReportName -notmatch '^[A-Za-z0-9-]{1,96}$') { throw 'A bounded report name is required.' }
$reportPath = Join-Path $env:SystemRoot ('Temp\' + $ReportName + '.json')
if (Test-Path -LiteralPath $reportPath) { throw 'Retained reports must not be replaced.' }
$report = [ordered]@{ success=$false; stage='input-guards'; cases=@();
    startedUtc=[DateTime]::UtcNow.ToString('o'); fskitWritesQualified=$false;
    qualification='native NTFS VHD mount recovery; not cold boot or hardware power interruption' }
$candidate = $null
$attached = $false
$batch = $null

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

function Test-NativeFiles($expected, [string]$root, [string]$acl, $fileId) {
    if ($root -notmatch '^[TR]:\\MachlinWriteCases-native-write-alias-20261006$' -or
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
        $result.ordinary = Test-NativeOrdinaryFiles $expected $root
    }
    $result.success = $true
    return $result
}

function Test-OriginalDisk {
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
                           matchingInjectedTornPages=@(); observedEvents=@() }
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
                if ($level -ne 3 -or -not $matching -or -not $data.ContainsKey('FileName') -or
                    $data['FileName'] -ne '\$LogFile' -or $data['FileReference'] -ne '2' -or
                    $data['TornStructureOffset'] -ne '0' -or
                    -not ($product.PSObject.Properties.Name -contains 'expectedTornLogPages')) {
                    throw 'Unattributed native torn-write event requires review.'
                }
                $expected = @($product.expectedTornLogPages | Where-Object {
                    $_.bufferOffset -eq $data['BufferOffset'] -and $_.blockIndex -eq $data['BlockIndex'] -and
                    $_.expectedSequenceNumber -eq $data['ExpectedSequenceNumber'] -and
                    $_.actualSequenceNumber -eq $data['ActualSequenceNumber']
                })
                if ($expected.Count -ne 1) { throw 'Native torn-page observation differs from the injected sector state.' }
                $row.matchingInjectedTornPages += $observed
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
    if ($batch.directory -notmatch '^C:\\Windows\\Temp\\MachlinNTFSImageRecovery-[A-Za-z0-9-]{1,48}$' -or
        @($batch.products).Count -lt 1 -or @($batch.products).Count -gt 256) { throw 'Unexpected private fixture directory or count.' }
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
        $case.preMountSha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($case.preMountSha256 -ne $product.expectedVhdSha256) { throw 'Candidate differs before native attachment.' }
        $case.mountStartedUtc = [DateTime]::UtcNow.ToString('o')
        $since = [DateTime]::Parse($case.mountStartedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
        $case.stage = 'native-mount'
        $image = Mount-DiskImage -ImagePath $candidate -StorageType VHD -Access ReadWrite -NoDriveLetter -PassThru
        $attached = $true
        $disk = $image | Get-Disk
        if (@($disk).Count -ne 1 -or $disk.Number -le 1 -or $disk.Size -ne 8589934592 -or
            $disk.PartitionStyle -ne 'GPT' -or $disk.IsBoot -or $disk.IsSystem -or $disk.IsOffline -or
            $disk.IsReadOnly -or [Guid]$disk.Guid -ne [Guid]$product.diskGuid) { throw 'Candidate virtual disk identity changed.' }
        $partition = Get-Partition -DiskNumber $disk.Number -PartitionNumber 2
        if ($partition.Offset -ne 16777216 -or $partition.Size -ne 8572108800 -or
            $partition.IsBoot -or $partition.IsSystem -or [Guid]$partition.Guid -ne [Guid]$product.partitionGuid -or
            [Guid]$partition.GptType -ne [Guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7') { throw 'Candidate partition identity changed.' }
        if (@(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Candidate letter became occupied.' }
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber 2 -AccessPath 'R:\'
        $volume = Get-Volume -DriveLetter R
        $encryption = Get-BitLockerVolume -MountPoint 'R:'
        $case.disk = $disk | Select-Object Number,Guid,UniqueId,BusType,Size,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly
        $case.partition = $partition | Select-Object DiskNumber,PartitionNumber,Guid,GptType,Offset,Size,IsBoot,IsSystem
        $case.volume = $volume | Select-Object UniqueId,DriveLetter,FileSystemType,FileSystemLabel,HealthStatus,Size,SizeRemaining
        $case.encryption = $encryption | Select-Object VolumeStatus,EncryptionMethod,EncryptionPercentage
        if ($volume.FileSystemType -ne 'NTFS' -or $volume.FileSystemLabel -ne 'MachlinNTFS' -or
            $volume.HealthStatus -ne 'Healthy' -or $encryption.VolumeStatus -ne 'FullyDecrypted' -or
            $encryption.EncryptionMethod -ne 'None' -or $encryption.EncryptionPercentage -ne 0) { throw 'Candidate is not the expected healthy plaintext NTFS volume.' }
        $case.stage = 'native-files-and-metadata'
        $case.nativeChecks = Test-NativeFiles $product $product.root $batch.targetAcl $batch.fileId
        $dirty = @(& "$env:SystemRoot\System32\fsutil.exe" dirty query 'R:' 2>&1)
        $dirtyExit = $LASTEXITCODE
        if ($dirtyExit -ne 0 -or ($dirty -join "`n") -notmatch 'Volume - R: is NOT Dirty') { throw 'Native clean-volume observation failed.' }
        $case.dirtyQuery = [ordered]@{ exitCode=$dirtyExit; output=$dirty }
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
