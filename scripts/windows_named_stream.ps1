# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Win32 ADS creation for Windows PowerShell 5.1/.NET Framework path handling.
# The caller must establish its scratch drive/partition ownership before calling.
function Write-CloudNamedStream([string]$Path, [string]$Name, [byte[]]$Value) {
    $maximumBytes = 1048576
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or
        $Name -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or
        $null -eq $Value -or $Value.Length -gt $maximumBytes) {
        throw 'A bounded named stream of an existing ordinary file is required.'
    }
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'A named stream requires an existing plain file.'
    }
    $parent = $file.Directory
    while ($null -ne $parent) {
        if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'A named stream path has a reparse ancestor.'
        }
        $parent = $parent.Parent
    }
    if (-not ('MachlinCloudNamedStream' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class MachlinCloudNamedStream {
    const uint GenericWrite = 0x40000000;
    const uint ExclusiveShare = 0;
    const uint CreateNew = 1;
    const uint OpenReparsePoint = 0x00200000;
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool WriteFile(SafeFileHandle handle, byte[] bytes, uint requested,
        out uint completed, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool FlushFileBuffers(SafeFileHandle handle);
    public static void Create(string name, byte[] bytes) {
        using (SafeFileHandle handle = CreateFileW(name, GenericWrite, ExclusiveShare,
                IntPtr.Zero, CreateNew, OpenReparsePoint, IntPtr.Zero)) {
            if (handle.IsInvalid) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW new named stream");
            }
            uint completed;
            if (!WriteFile(handle, bytes, (uint)bytes.Length, out completed, IntPtr.Zero)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteFile named stream");
            }
            if (completed != bytes.Length) {
                throw new IOException("Short named stream transfer; original partial stream retained");
            }
            if (!FlushFileBuffers(handle)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "FlushFileBuffers named stream");
            }
        }
    }
}
'@
    }
    [MachlinCloudNamedStream]::Create($file.FullName + ':' + $Name, $Value)
}
