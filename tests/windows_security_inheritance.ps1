# Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
# Pure private-object descriptor oracle. It never sets filesystem security,
# opens a client token, impersonates a principal or mounts a disk image.
param([Parameter(Mandatory=$true)][string]$InputManifest,
      [Parameter(Mandatory=$true)][string]$ReportPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath $ReportPath) { throw 'A fresh report path is required.' }
$input = Get-Content -LiteralPath $InputManifest -Raw | ConvertFrom-Json
if ($input.profile -ne 'file-generic-mapping-parent-owner-group' -or
    @($input.cases).Count -lt 1 -or @($input.cases).Count -gt 256) {
    throw 'Unsupported bounded inheritance profile.'
}
$source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class MachlinSecurityInheritance {
    const uint SEF_DACL_AUTO_INHERIT = 0x01;
    const uint SEF_SACL_AUTO_INHERIT = 0x02;
    const uint SEF_AVOID_PRIVILEGE_CHECK = 0x08;
    const uint SEF_AVOID_OWNER_CHECK = 0x10;
    const uint SEF_DEFAULT_OWNER_FROM_PARENT = 0x20;
    const uint SEF_DEFAULT_GROUP_FROM_PARENT = 0x40;
    const int MAX_DESCRIPTOR_BYTES = 4096;
    [StructLayout(LayoutKind.Sequential)]
    struct GenericMapping {
        public uint GenericRead, GenericWrite, GenericExecute, GenericAll;
    }
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool CreatePrivateObjectSecurityEx([In] byte[] parent,
        IntPtr creator, out IntPtr descriptor, IntPtr objectType, bool container,
        uint flags, IntPtr token, ref GenericMapping mapping);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool DestroyPrivateObjectSecurity(ref IntPtr descriptor);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

    public static byte[] Inherit(byte[] parent, bool container) {
        if (parent == null || parent.Length > MAX_DESCRIPTOR_BYTES)
            throw new ArgumentException("Unsupported parent descriptor size.");
        GenericMapping mapping = new GenericMapping {
            GenericRead=0x00120089, GenericWrite=0x00120116,
            GenericExecute=0x001200a0, GenericAll=0x001f01ff
        };
        IntPtr descriptor = IntPtr.Zero;
        // No object is secured by this diagnostic. Null-token construction is
        // expressly allowed by the documented paired avoid-check flags.
        uint flags = SEF_DACL_AUTO_INHERIT | SEF_SACL_AUTO_INHERIT |
            SEF_AVOID_PRIVILEGE_CHECK | SEF_AVOID_OWNER_CHECK |
            SEF_DEFAULT_OWNER_FROM_PARENT | SEF_DEFAULT_GROUP_FROM_PARENT;
        if (!CreatePrivateObjectSecurityEx(parent, IntPtr.Zero, out descriptor,
                IntPtr.Zero, container, flags, IntPtr.Zero, ref mapping))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > MAX_DESCRIPTOR_BYTES)
                throw new InvalidOperationException("Unexpected descriptor length.");
            byte[] output = new byte[length];
            Marshal.Copy(descriptor, output, 0, checked((int)length));
            return output;
        } finally {
            if (!DestroyPrivateObjectSecurity(ref descriptor))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
Add-Type -TypeDefinition $source -ReferencedAssemblies 'System.dll'
$report = [ordered]@{success=$false;profile=$input.profile;
    startedUtc=[DateTime]::UtcNow.ToString('o');cases=@();
    filesystemSecurityChanged=$false;tokenOpened=$false;impersonationUsed=$false;
    imagesMounted=0;automaticRetry=$false}
try {
    $names = [Collections.Generic.HashSet[string]]::new()
    foreach ($case in $input.cases) {
        if ($case.case -notmatch '^[a-z0-9-]{1,80}$' -or
            -not $names.Add($case.case) -or $case.container -isnot [bool]) {
            throw 'Malformed or duplicate inheritance case.'
        }
        $parent = [Convert]::FromBase64String($case.parent)
        $child = [MachlinSecurityInheritance]::Inherit($parent,$case.container)
        $report.cases += [ordered]@{case=$case.case;container=$case.container;
            parent=$case.parent;descriptor=[Convert]::ToBase64String($child);
            nativeCallSucceeded=$true}
    }
    $report.success=$true
} catch {
    $report.error=$_.Exception.ToString()
    throw
} finally {
    $report.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 -LiteralPath $ReportPath
}
