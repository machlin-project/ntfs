# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Replay each prepared cloud group exactly once and retain detached outcomes.
param([Parameter(Mandatory=$true)][string]$Packages,
      [Parameter(Mandatory=$true)][string]$BaseVhd,
      [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows_cloud_transport.ps1')
$packagesPath = (Assert-CloudPlainPath ([IO.Path]::GetFullPath($Packages)) $true).FullName
$basePath = (Assert-CloudPlainPath ([IO.Path]::GetFullPath($BaseVhd)) $false).FullName
$outputPath = [IO.Path]::GetFullPath($Output)
$insideTemp = $false
foreach ($temporary in @($env:TEMP,$env:RUNNER_TEMP)) {
    if ($temporary -and $outputPath.StartsWith(([IO.Path]::GetFullPath($temporary).TrimEnd('\') + '\'),
        [StringComparison]::OrdinalIgnoreCase)) { $insideTemp = $true }
}
if (-not $insideTemp -or $outputPath -notmatch '\\MachlinNTFSReplay-[A-Za-z0-9-]{1,64}$' -or
    (Test-Path -LiteralPath $outputPath)) { throw 'Use a fresh MachlinNTFSReplay-<tag> directory beneath runner TEMP.' }
[void](Assert-CloudPlainPath ([IO.Path]::GetDirectoryName($outputPath)) $true)
[void][IO.Directory]::CreateDirectory($outputPath)
$report = [ordered]@{schema_version=1;success=$false;stage='input-admission';groups=@();
    automatic_retry=$false;qualification='native VHD recovery only; no installed FSKit or hardware power-cut evidence'}
$collector = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\tests\windows_image_recovery.ps1'))
$guard = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\tests\windows_directory_guard.ps1'))
$collectorHash = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash.ToLowerInvariant()
$report.collector_sha256 = $collectorHash
function Save-Replay {
    [IO.File]::WriteAllText((Join-Path $outputPath 'replay.json'),($report | ConvertTo-Json -Depth 24) + "`n",
        [Text.UTF8Encoding]::new($false))
}
function Read-CloudJson([string]$Path) {
    $file = Assert-CloudPlainPath $Path $false
    if ($file.Length -gt 8388608) { throw 'Cloud JSON exceeds its byte budget.' }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}
Save-Replay
try {
    $manifest = Read-CloudJson (Join-Path $packagesPath 'result.json')
    if ($manifest.status -cne 'pass' -or $manifest.nativeWindowsPending -isnot [bool] -or
        -not $manifest.nativeWindowsPending -or @($manifest.groups).Count -lt 1 -or
        @($manifest.groups).Count -gt 16) { throw 'A complete bounded cloud package is required.' }
    $stages = @()
    $directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $reports = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index=0; $index -lt @($manifest.groups).Count; $index++) {
        $groupName = 'group-' + $index.ToString('00')
        $directory = Join-Path $packagesPath $groupName
        $batchPath = Join-Path $directory 'batch.json'
        $batch = Read-CloudJson $batchPath
        $transfers = @(Read-CloudJson (Join-Path $directory 'transfer.json'))
        $entry = $manifest.groups[$index]
        $reportName = $entry.reportName
        if ($batch.cloudInput -isnot [bool] -or -not $batch.cloudInput -or
            $batch.directory -cnotmatch '^C:\\Windows\\Temp\\MachlinNTFSImageRecovery-[A-Za-z0-9-]{1,48}$' -or
            -not $directories.Add($batch.directory) -or (Test-Path -LiteralPath $batch.directory) -or
            $reportName -cnotmatch '^[A-Za-z0-9-]{1,96}$' -or -not $reports.Add($reportName) -or
            @($batch.products).Count -lt 1 -or @($batch.products).Count -gt 8 -or
            $transfers.Count -ne @($batch.products).Count + 1) { throw 'Unexpected/reused cloud group identity.' }
        $nativeReport = Join-Path $env:SystemRoot ('Temp\' + $reportName + '.json')
        if (Test-Path -LiteralPath $nativeReport) { throw 'A prior native report exists; do not retry it.' }
        [void](Assert-CloudPlainPath ([IO.Path]::GetDirectoryName($batch.directory)) $true)
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $sources = @()
        foreach ($expected in $transfers) {
            if (-not $names.Add($expected.name)) { throw 'Duplicate cloud transfer filename.' }
            if ($expected.name -ceq 'base.vhd') {
                if ($expected.sha256 -cne $batch.baseVhdSha256 -or $expected.bytes -ne $batch.baseVhdBytes) {
                    throw 'Baseline transfer identity differs.'
                }
            } else {
                $products = @($batch.products | Where-Object { $_.preparedVhdName -ceq $expected.name })
                if ($products.Count -ne 1 -or $products[0].expectedVhdSha256 -cne $expected.sha256 -or
                    $products[0].preparedVhdBytes -ne $expected.bytes -or
                    $products[0].preparedVhdName -cne ('input-' + $products[0].case + '.vhd')) {
                    throw 'Product transfer identity differs.'
                }
            }
            $source = Resolve-CloudTransfer $packagesPath $basePath $expected
            if ((Get-DiskImage -ImagePath $source).Attached) { throw 'A producer input is attached.' }
            $sources += [pscustomobject]@{path=$source;name=$expected.name;sha256=$expected.sha256}
        }
        if (-not $names.Contains('base.vhd')) { throw 'Missing baseline transfer.' }
        $stages += [pscustomobject]@{name=$groupName;batch=$batch;batchPath=$batchPath;sources=$sources;
            reportName=$reportName;nativeReport=$nativeReport}
    }
    # Complete input admission precedes every candidate attachment in every group.
    foreach ($stage in $stages) {
        $groupOutput = Join-Path $outputPath $stage.name
        [void][IO.Directory]::CreateDirectory($groupOutput)
        $state = [ordered]@{name=$stage.name;success=$false;stage='stage-verified-inputs';postimages=@()}
        $report.groups += $state
        $report.stage = $stage.name; Save-Replay
        try {
            [void][IO.Directory]::CreateDirectory($stage.batch.directory)
            foreach ($source in $stage.sources) {
                Copy-CloudFile $source.path (Join-Path $stage.batch.directory $source.name) $source.sha256
            }
            $batchHash = (Get-FileHash -LiteralPath $stage.batchPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $stagedManifest = Join-Path $stage.batch.directory 'batch.json'
            Copy-CloudFile $stage.batchPath $stagedManifest $batchHash
            $state.stage = 'read-only-admission'; Save-Replay
            $state.guard = & $guard -Collector $collector -CollectorHash $collectorHash -BatchManifest $stagedManifest
            $state.stage = 'native-recovery'; Save-Replay
            & $collector -BatchManifest $stagedManifest -ReportName $stage.reportName
            $observed = Read-CloudJson $stage.nativeReport
            if (-not $observed.success -or @($observed.cases).Count -ne @($stage.batch.products).Count) {
                throw 'Native collector did not complete the entire admitted group.'
            }
            $state.success = $true; $state.stage = 'complete'
        } finally {
            if (Test-Path -LiteralPath $stage.nativeReport) {
                $hash = (Get-FileHash -LiteralPath $stage.nativeReport -Algorithm SHA256).Hash.ToLowerInvariant()
                Copy-CloudFile $stage.nativeReport (Join-Path $groupOutput 'native-report.json') $hash
            }
            # Never copy/upload attached media, even when preserving a failed case.
            foreach ($product in $stage.batch.products) {
                $candidate = Join-Path $stage.batch.directory ($product.case + '.vhd')
                if (-not (Test-Path -LiteralPath $candidate)) { continue }
                [void](Assert-CloudPlainPath $candidate $false)
                if ((Get-DiskImage -ImagePath $candidate).Attached) {
                    $state.postimages += [ordered]@{case=$product.case;retained=$false;attached=$true}
                    throw 'A failed candidate is still attached; media was not archived.'
                }
                $hash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
                if (Test-Path -LiteralPath $stage.nativeReport) {
                    $native = Read-CloudJson $stage.nativeReport
                    $cases = @($native.cases | Where-Object { $_.case -ceq $product.case })
                    if ($cases.Count -gt 1 -or ($cases.Count -eq 1 -and $cases[0].success -and
                        $cases[0].postDetachSha256 -cne $hash)) {
                        throw 'Detached postimage differs from its original native report.'
                    }
                }
                Copy-CloudFile $candidate (Join-Path $groupOutput ($product.case + '.vhd')) $hash
                $state.postimages += [ordered]@{case=$product.case;retained=$true;attached=$false;sha256=$hash;
                    bytes=(Get-Item -LiteralPath $candidate).Length}
            }
            Save-Replay
        }
    }
    $report.success = $true; $report.stage = 'complete'
} catch {
    $report.error = $_.Exception.ToString()
} finally { Save-Replay }
if (-not $report.success) { throw ('Cloud native replay failed at ' + $report.stage + '; see replay.json') }
