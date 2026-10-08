# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Local, bounded artifact mapping. No volume or device operations.
function Assert-CloudPlainPath([string]$Path, [bool]$Directory) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Cloud artifact must be a plain file or directory of the expected type.'
    }
    $parent = if ($Directory) { $item.Parent } else { $item.Directory }
    while ($null -ne $parent) {
        if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Cloud artifact has a reparse ancestor.' }
        $parent = $parent.Parent
    }
    return $item
}

function Resolve-CloudTransfer([string]$Packages, [string]$BaseVhd, $Expected) {
    if ($Expected.name -ceq 'base.vhd') {
        $path = $BaseVhd
    } elseif ($Expected.name -cmatch '^input-([A-Za-z0-9-]{1,80})\.vhd$') {
        # Deliberately ignore producer-local paths in transfer.json.
        $path = Join-Path (Join-Path $Packages $Matches[1]) $Expected.name
    } else { throw 'Unexpected cloud transfer filename.' }
    if ($Expected.bytes -lt 1 -or $Expected.bytes -gt 134217728 -or
        $Expected.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Cloud transfer exceeds its byte/hash bounds.' }
    $file = Assert-CloudPlainPath $path $false
    if ($file.Length -ne $Expected.bytes -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected.sha256) {
        throw 'Cloud transfer length/hash differs from its manifest.'
    }
    return $file.FullName
}

function Copy-CloudFile([string]$Source, [string]$Destination, [string]$Hash) {
    [void](Assert-CloudPlainPath $Source $false)
    if (Test-Path -LiteralPath $Destination) { throw 'A retained artifact cannot be replaced.' }
    [void](Assert-CloudPlainPath ([IO.Path]::GetDirectoryName($Destination)) $true)
    $inputFile = [IO.FileStream]::new($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $outputFile = [IO.FileStream]::new($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $inputFile.CopyTo($outputFile,1048576); $outputFile.Flush($true) } finally { $outputFile.Dispose() }
    } finally { $inputFile.Dispose() }
    if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Hash) {
        throw 'Copied artifact changed; preserve the partial output.'
    }
}
