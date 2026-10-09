# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Read-only security observation of a new copy of one exact retained failed postimage.
param([Parameter(Mandatory=$true)][string]$Packages,
      [Parameter(Mandatory=$true)][string]$Replay,
      [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows_scratch_guard.ps1')
. (Join-Path $PSScriptRoot 'windows_cloud_transport.ps1')
$outputPath = [IO.Path]::GetFullPath($Output)
$tempPath = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
if (-not $outputPath.StartsWith($tempPath, [StringComparison]::OrdinalIgnoreCase) -or
    $outputPath -notmatch '\\MachlinNTFSSecurityReadonly-[A-Za-z0-9-]{1,64}$' -or
    (Test-Path -LiteralPath $outputPath)) { throw 'Use a fresh MachlinNTFSSecurityReadonly tag under RUNNER_TEMP.' }
$parent = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($outputPath))
while ($null -ne $parent) {
    if (-not $parent.Exists -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Every observation output ancestor must be an existing plain directory.'
    }
    $parent = $parent.Parent
}
[void][IO.Directory]::CreateDirectory($outputPath)
$evidence = Join-Path $outputPath 'evidence'
[void][IO.Directory]::CreateDirectory($evidence)
$vhd = Join-Path $outputPath 'postimage-copy.vhd'
$reportPath = Join-Path $evidence 'report.json'
$attached = $false
$report = [ordered]@{schema_version=1;status='running';stage='input-admission';
    provenance='Read-only diagnosis of original failed f415c6b native security comparison';
    source_run=37869063560;package_artifact=11590375707;replay_artifact=11589579895;
    original_failed_verdict_replaced=$false;comparisons=@();
    cache_semantics_qualified=$false;native_recovery_qualified=$false;
    machine_policy_changed=$false;phases=@();commands=@();errors=@()}
$report.platform = [ordered]@{system='Windows';version=[Environment]::OSVersion.Version.ToString();
    powershell=$PSVersionTable.PSVersion.ToString()}
$report.sources = @('inspect_windows_security.ps1','windows_cloud_transport.ps1',
    'windows_scratch_guard.ps1','collect_windows_corpus.py') | ForEach-Object {
    [ordered]@{file=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $_) -Algorithm SHA256).Hash.ToLowerInvariant()}
}
function Save-Report {
    [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
}
function Native([string]$Name, [string]$Executable, [string[]]$Arguments) {
    $quoted = @($Arguments | ForEach-Object {
        '"' + ([regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1')) + '"'
    })
    $stdout = Join-Path $evidence ($Name + '.stdout')
    $stderr = Join-Path $evidence ($Name + '.stderr')
    $process = Start-Process -FilePath $Executable -ArgumentList ($quoted -join ' ') -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $processHandle = $process.Handle
    if (-not $process.WaitForExit(120000)) {
        $process.Kill(); $process.WaitForExit(); throw 'Native probe command exceeded its deadline.'
    }
    $process.Refresh()
    if ((Get-Item -LiteralPath $stdout).Length + (Get-Item -LiteralPath $stderr).Length -gt 8388608) {
        throw 'Native probe command exceeded its output bound.'
    }
    $report.commands += [ordered]@{name=$Name;arguments=$Arguments;exit_code=$process.ExitCode}
    Save-Report
    if ($process.ExitCode -ne 0) { throw ($Name + ' failed; original outputs retained without retry.') }
}
function Guard([bool]$ReadOnly) {
    $image = Get-DiskImage -ImagePath $vhd
    $disks = @($image | Get-Disk)
    if ($disks.Count -ne 1) { throw 'Probe VHD must resolve to exactly one disk.' }
    $disk = Assert-ScratchDisk $image $disks[0] $vhd $baseline.disk_bytes $protected $baseline.disk $ReadOnly
    $parts = @(Get-Partition -DiskNumber $disk.Number | Where-Object {
        [Guid]$_.GptType -eq [Guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
    })
    if ($parts.Count -ne 1) { throw 'Probe VHD must contain one basic-data partition.' }
    return (Assert-ScratchPartition $parts[0] $disk $baseline.partition)
}
function Drive([bool]$ReadOnly) {
    $part = Guard $ReadOnly
    $disk = (Get-DiskImage -ImagePath $vhd | Get-Disk)
    [void](Assert-ScratchDrive @(Get-Partition -DriveLetter R) (Get-Volume -DriveLetter R) `
        $disk $part 'R' $baseline.volume)
}
function Attach([bool]$ReadOnly) {
    if ((Get-DiskImage -ImagePath $vhd).Attached -or
        @(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0 -or
        (Test-Path -LiteralPath 'R:\')) { throw 'Probe disk is attached or its drive letter is occupied.' }
    $access = if ($ReadOnly) { 'ReadOnly' } else { 'ReadWrite' }
    Mount-DiskImage -ImagePath $vhd -StorageType VHD -Access $access -NoDriveLetter | Out-Null
    $script:attached = $true
    $part = Guard $ReadOnly
    Add-PartitionAccessPath -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -AccessPath 'R:\'
    Drive $ReadOnly
}
function Detach([bool]$ReadOnly) {
    [void](Guard $ReadOnly)
    Dismount-DiskImage -ImagePath $vhd
    if ((Get-DiskImage -ImagePath $vhd).Attached) { throw 'Probe VHD did not detach.' }
    $script:attached = $false
}
function Checked-Source([string]$Path, [string]$Hash) {
    $file = Assert-CloudPlainPath ([IO.Path]::GetFullPath($Path)) $false
    if ($file.Length -le 0 -or $file.Length -gt 134217728 -or
        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Hash) {
        throw 'Original diagnostic input does not match its immutable source pin.'
    }
    return $file.FullName
}
function Dacl-Bytes($Descriptor) {
    if ($null -eq $Descriptor.DiscretionaryAcl) { return $null }
    $value = [byte[]]::new($Descriptor.DiscretionaryAcl.BinaryLength)
    $Descriptor.DiscretionaryAcl.GetBinaryForm($value,0)
    return [Convert]::ToBase64String($value)
}
Save-Report
try {
    $packagesPath = (Assert-CloudPlainPath ([IO.Path]::GetFullPath($Packages)) $true).FullName
    $replayPath = (Assert-CloudPlainPath ([IO.Path]::GetFullPath($Replay)) $true).FullName
    $batchPath = Checked-Source (Join-Path $packagesPath 'windows-directory-packages\group-00\batch.json') `
        'a87e1c035d35d535a692a53f1a2667f1a930aed837cf4f17b7bcd3fb2a986f64'
    $nativePath = Checked-Source (Join-Path $replayPath 'group-00\native-report.json') `
        '5aa861a95fc88afd366cd0742191be24c1e8f108a04d8b2f62363424bb0b0cbe'
    $replayReportPath = Checked-Source (Join-Path $replayPath 'replay.json') `
        'bd74c00087446c0dbd8d393ebb0cb6d4b231cb187951a227d60df3da2d9a9e15'
    $beforeHash = '25802fa343d845b89516524850c35a148c4bac283015a6aff5832c70b8de6ff3'
    $afterHash = '4810ae5bf3947c7148ad1445edacd7ec1c0a21142b87e5bb8363963f9c0cddd7'
    $before = Checked-Source (Join-Path $packagesPath 'windows-directory-packages\directory-full\input-directory-full.vhd') $beforeHash
    $after = Checked-Source (Join-Path $replayPath 'group-00\directory-full.vhd') $afterHash
    $batch = Get-Content -Raw -LiteralPath $batchPath | ConvertFrom-Json
    $native = Get-Content -Raw -LiteralPath $nativePath | ConvertFrom-Json
    $originalReplay = Get-Content -Raw -LiteralPath $replayReportPath | ConvertFrom-Json
    $products = @($batch.products | Where-Object { $_.case -ceq 'directory-full' })
    if ($products.Count -ne 1 -or $native.success -or $originalReplay.success -or
        @($native.cases).Count -ne 1 -or $native.cases[0].case -cne 'directory-full' -or
        $native.cases[0].success -or -not $native.failedCandidateDetached -or
        $products[0].expectedVhdSha256 -cne $beforeHash -or
        $native.cases[0].preMountSha256 -cne $beforeHash) { throw 'Unexpected original failure identity.' }
    $product = $products[0]
    $postimages = @($originalReplay.groups[0].postimages)
    if ($postimages.Count -ne 1 -or $postimages[0].case -cne 'directory-full' -or
        -not $postimages[0].retained -or $postimages[0].attached -or
        $postimages[0].sha256 -cne $afterHash) { throw 'Original failed postimage was not retained detached.' }
    $collector = Join-Path $PSScriptRoot '..\tests\windows_image_recovery.ps1'
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($collector,[ref]$tokens,[ref]$errors)
    if (@($errors).Count) { throw 'Collector parser failed before read-only admission.' }
    $functions = @($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Test-NativeSequenceProfile'
    },$false))
    if ($functions.Count -ne 1) { throw 'Missing bounded original namespace profile.' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
    [void](Test-NativeSequenceProfile $product $product.root)
    $report.collector_sha256 = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash.ToLowerInvariant()
    $baseline = [pscustomobject]@{disk_bytes=$batch.diskBytes;disk=$native.cases[0].disk;
        partition=$native.cases[0].partition;volume=$native.cases[0].volume}
    if ([Guid]$baseline.disk.Guid -ne [Guid]$product.diskGuid -or
        [Guid]$baseline.partition.Guid -ne [Guid]$product.partitionGuid -or
        $baseline.partition.Offset -ne $batch.partitionOffset -or
        $baseline.partition.Size -ne $batch.partitionBytes) { throw 'Original geometry disagrees.' }
    if ((Get-DiskImage -ImagePath $before).Attached -or (Get-DiskImage -ImagePath $after).Attached) {
        throw 'An immutable original input is attached.'
    }
    Copy-Item -LiteralPath $batchPath -Destination (Join-Path $evidence 'original-batch.json')
    Copy-Item -LiteralPath $nativePath -Destination (Join-Path $evidence 'original-native-report.json')
    Copy-Item -LiteralPath $replayReportPath -Destination (Join-Path $evidence 'original-replay.json')
    $protected = @((Get-Disk).Number)
    $report.protected_disk_numbers = $protected
    $report.before_sha256 = $beforeHash; $report.after_sha256 = $afterHash
    Copy-Item -LiteralPath $after -Destination $vhd
    [void](Checked-Source $vhd $afterHash)
    $report.stage = 'read-only-copy-observation'; Save-Report
    Attach $true
    $selected = @($product.sequenceObjects | Where-Object { $_.directory }) +
        @($product.sequenceObjects | Where-Object { -not $_.directory } | Select-Object -First 1)
    foreach ($entry in $selected) {
        Drive $true
        $path = Join-Path $product.root $entry.relativePath
        $expectedRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Convert]::FromBase64String($entry.securityDescriptor),0)
        $actualManaged = Get-Acl -LiteralPath $path
        $report.comparisons += [ordered]@{path=$path;relativePath=$entry.relativePath;reference=$entry.reference;
            expectedDescriptor=$entry.securityDescriptor;
            expectedSddl=$expectedRaw.GetSddlForm([Security.AccessControl.AccessControlSections]::All);
            actualManagedSddl=$actualManaged.Sddl;
            actualManagedDescriptor=[Convert]::ToBase64String($actualManaged.GetSecurityDescriptorBinaryForm())}
        Save-Report
    }
    Drive $true
    Native 'read-only-kernel-descriptors-and-corpus' 'python' @((Join-Path $PSScriptRoot 'collect_windows_corpus.py'),
        '--volume','R:\','--tree',$product.root.Substring(3),'--output',(Join-Path $evidence 'corpus'),
        '--max-image-bytes',([string]$batch.diskBytes),'--max-entries','512')
    Drive $true
    $corpus = Get-Content -Raw -LiteralPath (Join-Path $evidence 'corpus\manifest.json') | ConvertFrom-Json
    if ($corpus.acquisition_status -cne 'complete') { throw 'Read-only kernel acquisition did not complete.' }
    foreach ($row in $report.comparisons) {
        $reference = [UInt64]::Parse($row.reference,[Globalization.CultureInfo]::InvariantCulture)
        $hex = $reference.ToString('x16',[Globalization.CultureInfo]::InvariantCulture)
        $matches = @($corpus.entries | Where-Object { $_.reference -ceq $hex })
        if ($matches.Count -ne 1) { throw 'Exact original object reference was not acquired.' }
        $actualBytes = [Convert]::FromBase64String($matches[0].security_descriptor_base64)
        $expectedRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Convert]::FromBase64String($row.expectedDescriptor),0)
        $actualRaw = [Security.AccessControl.RawSecurityDescriptor]::new($actualBytes,0)
        $row.actualKernelDescriptor = $matches[0].security_descriptor_base64
        $row.actualKernelSddl = $actualRaw.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
        $row.expectedDacl = Dacl-Bytes $expectedRaw
        $row.actualKernelDacl = Dacl-Bytes $actualRaw
        $row.ownerEqual = $expectedRaw.Owner.Value -ceq $actualRaw.Owner.Value
        $row.groupEqual = $expectedRaw.Group.Value -ceq $actualRaw.Group.Value
        $row.daclBytesEqual = $row.expectedDacl -ceq $row.actualKernelDacl
        $row.kernelSddlEqual = $row.expectedSddl -ceq $row.actualKernelSddl
        $row.managedSddlEqual = $row.expectedSddl -ceq $row.actualManagedSddl
    }
    Detach $true
    [void](Checked-Source $vhd $afterHash)
    [void](Checked-Source $before $beforeHash)
    [void](Checked-Source $after $afterHash)
    $report.copy_and_originals_unchanged = $true
    $report.status = 'complete'; $report.stage = 'complete'
} catch {
    $report.status = 'failed'; $report.errors += $_.Exception.ToString()
    $report.error_position = $_.InvocationInfo.PositionMessage
    $report.error_script_stack = $_.ScriptStackTrace
} finally {
    if ($attached) {
        try {
            Dismount-DiskImage -ImagePath $vhd
            $report.diagnostic_copy_detached = -not (Get-DiskImage -ImagePath $vhd).Attached
        } catch { $report.errors += $_.Exception.ToString() }
    }
    Save-Report
}
if ($report.status -cne 'complete') { throw ('Read-only security observation failed; retain ' + $reportPath) }
