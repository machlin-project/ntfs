# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Observe per-volume short-name policy on a newly authored disposable VHD only.
param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows_scratch_guard.ps1')
$outputPath = [IO.Path]::GetFullPath($Output)
$tempPath = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
if (-not $outputPath.StartsWith($tempPath, [StringComparison]::OrdinalIgnoreCase) -or
    $outputPath -notmatch '\\MachlinNTFSFlags-[A-Za-z0-9-]{1,64}$' -or
    (Test-Path -LiteralPath $outputPath)) { throw 'Use a fresh MachlinNTFSFlags tag under RUNNER_TEMP.' }
[void][IO.Directory]::CreateDirectory($outputPath)
$evidence = Join-Path $outputPath 'evidence'
[void][IO.Directory]::CreateDirectory($evidence)
$baselinePath = Join-Path $outputPath 'MachlinNTFSCloud-baseline'
$vhd = Join-Path $outputPath 'policy.vhd'
$reportPath = Join-Path $evidence 'report.json'
$attached = $false
$report = [ordered]@{schema_version=1;status='running';stage='bootstrap';
    provenance='Windows native per-volume short-name policy observations';
    source='https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-8dot3name';
    machine_policy_changed=$false;phases=@();commands=@();errors=@()}
$report.platform = [ordered]@{system='Windows';version=[Environment]::OSVersion.Version.ToString();
    powershell=$PSVersionTable.PSVersion.ToString()}
$report.sources = @('probe_windows_volume_flags.ps1','bootstrap_windows_ntfs.ps1',
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
Save-Report
try {
    & (Join-Path $PSScriptRoot 'bootstrap_windows_ntfs.ps1') -Output $baselinePath
    $baseline = Get-Content -Raw -LiteralPath (Join-Path $baselinePath 'bootstrap.json') | ConvertFrom-Json
    $baseVhd = Join-Path $baselinePath 'base.vhd'
    if ($baseline.acquisition_status -cne 'complete' -or -not $baseline.vhd.detached -or
        (Get-DiskImage -ImagePath $baseVhd).Attached -or
        (Get-FileHash -LiteralPath $baseVhd -Algorithm SHA256).Hash.ToLowerInvariant() -cne $baseline.vhd.sha256) {
        throw 'Fresh baseline did not complete detached and unchanged.'
    }
    Copy-Item -LiteralPath $baselinePath -Destination (Join-Path $evidence 'baseline') -Recurse
    $protected = @((Get-Disk).Number)
    $report.protected_disk_numbers = $protected
    $report.disk = $baseline.disk; $report.partition = $baseline.partition
    $report.baseline_sha256 = $baseline.vhd.sha256
    Copy-Item -LiteralPath $baseVhd -Destination $vhd
    $fsutil = Join-Path $env:SystemRoot 'System32\fsutil.exe'
    foreach ($phase in @([pscustomobject]@{name='original';setting=$null},
        [pscustomobject]@{name='enabled';setting='0'},
        [pscustomobject]@{name='disabled';setting='1'},
        [pscustomobject]@{name='reenabled';setting='0'})) {
        $report.stage = $phase.name; Save-Report
        Attach $false
        Drive $false
        Native ($phase.name + '-query-before') $fsutil @('8dot3name','query','R:')
        if ($null -ne $phase.setting) {
            Drive $false
            # Four arguments always include the admitted volume. No registry/default change.
            Native ($phase.name + '-set') $fsutil @('8dot3name','set','R:',$phase.setting)
            Drive $false
            Native ($phase.name + '-query-after') $fsutil @('8dot3name','query','R:')
        }
        Drive $false
        Native ($phase.name + '-chkdsk') (Join-Path $env:SystemRoot 'System32\chkdsk.exe') @('R:')
        Drive $false
        [MachlinCloudVolumeFlush]::Flush('\\.\R:')
        Detach $false
        $hash = (Get-FileHash -LiteralPath $vhd -Algorithm SHA256).Hash.ToLowerInvariant()
        $phasePath = Join-Path $evidence $phase.name
        [void][IO.Directory]::CreateDirectory($phasePath)
        Copy-Item -LiteralPath $vhd -Destination (Join-Path $phasePath 'detached.vhd')
        if ((Get-FileHash -LiteralPath (Join-Path $phasePath 'detached.vhd') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash) {
            throw 'Detached snapshot copy changed its bytes.'
        }
        Attach $true
        Drive $true
        Native ($phase.name + '-corpus') 'python' @((Join-Path $PSScriptRoot 'collect_windows_corpus.py'),
            '--volume','R:\','--tree',$baseline.root_name,'--output',(Join-Path $phasePath 'corpus'),
            '--max-image-bytes',([string]$baseline.disk_bytes),'--max-entries','32')
        Detach $true
        if ((Get-FileHash -LiteralPath $vhd -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash -or
            (Get-FileHash -LiteralPath $baseVhd -Algorithm SHA256).Hash.ToLowerInvariant() -cne $baseline.vhd.sha256) {
            throw 'Read-only acquisition or policy probe changed frozen evidence.'
        }
        $report.phases += [ordered]@{name=$phase.name;setting=$phase.setting;vhd_sha256=$hash;detached=$true;
            corpus_sha256=(Get-FileHash -LiteralPath (Join-Path $phasePath 'corpus\manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()}
        Save-Report
    }
    $report.status = 'complete'; $report.stage = 'complete'
} catch {
    $report.status = 'failed'; $report.errors += $_.Exception.ToString()
    $report.error_position = $_.InvocationInfo.PositionMessage
} finally {
    if ($attached) {
        try { Dismount-DiskImage -ImagePath $vhd } catch { $report.errors += $_.Exception.ToString() }
    }
    Save-Report
}
if ($report.status -cne 'complete') { throw ('Volume policy probe failed; retain ' + $reportPath) }
