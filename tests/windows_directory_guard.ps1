# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Read-only admission of all products before the first native mount.
param([Parameter(Mandatory=$true)][string]$Collector,
      [Parameter(Mandatory=$true)][string]$CollectorHash,
      [Parameter(Mandatory=$true)][string]$BatchManifest)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($CollectorHash -notmatch '^[a-f0-9]{64}$' -or
    (Get-FileHash -LiteralPath $Collector -Algorithm SHA256).Hash.ToLowerInvariant() -cne $CollectorHash) {
    throw 'Collector source differs from the retained input.'
}
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Collector, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) { throw 'Collector parser errors.' }
foreach ($name in @('Test-NativeSequenceProfile','Test-NativeTornMetadataProfile')) {
    $functions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $false))
    if ($functions.Count -ne 1) { throw 'Collector function identity differs.' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
if ((Get-Item -LiteralPath $BatchManifest).Length -gt 8388608) { throw 'Batch manifest exceeds its bound.' }
$batch = Get-Content -LiteralPath $BatchManifest -Raw | ConvertFrom-Json
if ($batch.directory -notmatch '^C:\\Windows\\Temp\\MachlinNTFSImageRecovery-[A-Za-z0-9-]{1,48}$' -or
    @($batch.products).Count -lt 1 -or @($batch.products).Count -gt 8) {
    throw 'Unexpected private fixture directory or group size.'
}
$folder = Get-Item -LiteralPath $batch.directory
if (-not $folder.PSIsContainer -or ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'A plain private fixture directory is required.'
}
$names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$diskIds = [Collections.Generic.HashSet[Guid]]::new()
$partitionIds = [Collections.Generic.HashSet[Guid]]::new()
$files = @([pscustomobject]@{name='base.vhd';bytes=$batch.baseVhdBytes;sha256=$batch.baseVhdSha256})
$storage = [long]1073741824
foreach ($product in $batch.products) {
    if ($product.case -notmatch '^[A-Za-z0-9-]{1,80}$' -or -not $names.Add($product.case) -or
        -not $diskIds.Add([Guid]$product.diskGuid) -or -not $partitionIds.Add([Guid]$product.partitionGuid) -or
        $product.preparedVhdName -cne ('input-' + $product.case + '.vhd') -or @($product.patches).Count -ne 0) {
        throw 'Unexpected or repeated product identity.'
    }
    [void](Test-NativeSequenceProfile $product $product.root)
    [void](Test-NativeTornMetadataProfile $product $product.root)
    if (Test-Path -LiteralPath (Join-Path $batch.directory ($product.case + '.vhd'))) {
        throw 'A prior native candidate exists; do not retry it.'
    }
    $files += [pscustomobject]@{name=$product.preparedVhdName;bytes=$product.preparedVhdBytes;sha256=$product.expectedVhdSha256}
    $storage += [long]$product.preparedVhdBytes
}
foreach ($expected in $files) {
    $path = Join-Path $batch.directory $expected.name
    $file = Get-Item -LiteralPath $path
    if ($expected.bytes -lt 1 -or $expected.bytes -gt 134217728 -or $expected.sha256 -notmatch '^[a-f0-9]{64}$' -or
        $file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $file.Length -ne $expected.bytes -or (Get-DiskImage -ImagePath $path).Attached -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected.sha256) {
        throw 'Fixture bytes or detachment differ.'
    }
}
if ((Get-PSDrive -Name C).Free -lt $storage -or
    @(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0 -or (Test-Path -LiteralPath 'R:\')) {
    throw 'Insufficient storage or occupied candidate drive letter.'
}
return [ordered]@{success=$true;products=@($batch.products).Count;parserErrors=0;
    candidateMounts=0;filesystemMutations=0;collectorSha256=$CollectorHash}
