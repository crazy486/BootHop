# Shared Windows-only handle helpers for the staging and audit scripts. Handles
# use FILE_SHARE_READ only, so a held input cannot be replaced, renamed, or
# modified while its bytes are consumed. The scripts still perform explicit
# canonical/reparse checks before opening each handle.
if ($null -eq ('WindowsFileHandle' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class WindowsFileHandle {
    [StructLayout(LayoutKind.Sequential)] private struct Info {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
        public System.Runtime.InteropServices.ComTypes.FILETIME Access; public System.Runtime.InteropServices.ComTypes.FILETIME Write;
        public uint Volume; public uint SizeHigh; public uint SizeLow; public uint Links; public uint IndexHigh; public uint IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, [Out] char[] path, uint length, uint flags);
    public static FileStream OpenFile(string path) {
        var h = CreateFileW(path, 0x80000000u, 1u, IntPtr.Zero, 3u, 0x00200000u, IntPtr.Zero);
        if (h.IsInvalid) { h.Dispose(); throw new IOException("CreateFileW file failed: " + Marshal.GetLastWin32Error()); }
        return new FileStream(h, FileAccess.Read, 1, false);
    }
    public static FileStream OpenDirectory(string path) {
        var h = CreateFileW(path, 0x80000000u, 1u, IntPtr.Zero, 3u, 0x02000000u, IntPtr.Zero);
        if (h.IsInvalid) { h.Dispose(); throw new IOException("CreateFileW directory failed: " + Marshal.GetLastWin32Error()); }
        return new FileStream(h, FileAccess.Read, 1, false);
    }
    public static string Identity(SafeFileHandle handle) {
        Info info; if (!GetFileInformationByHandle(handle, out info)) throw new IOException("GetFileInformationByHandle failed: " + Marshal.GetLastWin32Error());
        var n = GetFinalPathNameByHandleW(handle, null, 0, 0); if (n == 0) throw new IOException("GetFinalPathNameByHandleW failed: " + Marshal.GetLastWin32Error());
        var chars = new char[n + 1]; var got = GetFinalPathNameByHandleW(handle, chars, (uint)chars.Length, 0); if (got == 0 || got >= chars.Length) throw new IOException("GetFinalPathNameByHandleW returned an invalid path");
        return new string(chars, 0, (int)got) + "|" + info.Volume.ToString("X8") + ":" + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8");
    }
}
'@
}

function Normalize-HeldPath([string] $path) { if ($path.StartsWith('\\?\')) { return $path.Substring(4) }; return $path }
function Open-HeldRead([string] $path, [string] $label, [string] $expectedCanonical = $null) {
    try { $stream = [WindowsFileHandle]::OpenFile($path) } catch { throw "Held $label open failed: $($_.Exception.Message)" }
    try {
        $identity = [WindowsFileHandle]::Identity($stream.SafeFileHandle); $final = Normalize-HeldPath (($identity -split '\|')[0])
        if ($null -ne $expectedCanonical -and -not [string]::Equals($final, $expectedCanonical, [StringComparison]::Ordinal)) { throw "Held $label final path differs from canonical path" }
        return [pscustomobject]@{ Stream=$stream; Identity=$identity; Canonical=$final; Path=$path }
    } catch { $stream.Dispose(); throw }
}
function Open-HeldDirectory([string] $path, [string] $label, [string] $expectedCanonical = $null) {
    try { $stream = [WindowsFileHandle]::OpenDirectory($path) } catch { throw "Held $label directory open failed: $($_.Exception.Message)" }
    try {
        $identity = [WindowsFileHandle]::Identity($stream.SafeFileHandle); $final = Normalize-HeldPath (($identity -split '\|')[0])
        if ($null -ne $expectedCanonical -and -not [string]::Equals($final, $expectedCanonical, [StringComparison]::Ordinal)) { throw "Held $label final path differs from canonical path" }
        return [pscustomobject]@{ Stream=$stream; Identity=$identity; Canonical=$final; Path=$path }
    } catch { $stream.Dispose(); throw }
}
function Assert-HeldIdentity($held, [string] $label) {
    if ($null -eq $held -or $held.Stream.SafeFileHandle.IsClosed) { throw "Held $label handle is closed" }
    $identity = [WindowsFileHandle]::Identity($held.Stream.SafeFileHandle)
    if (-not [string]::Equals([string]$identity, [string]$held.Identity, [StringComparison]::Ordinal)) { throw "Held $label identity changed" }
}
function Reset-Held($held) { Assert-HeldIdentity $held 'file'; $held.Stream.Position = 0 }
function Get-HeldHash($held, [string] $label = 'file') {
    Assert-HeldIdentity $held $label; $held.Stream.Position = 0; $sha = [Security.Cryptography.SHA256]::Create()
    try { $result = ([BitConverter]::ToString($sha.ComputeHash($held.Stream)) -replace '-','').ToLowerInvariant() } finally { $sha.Dispose(); $held.Stream.Position = 0 }
    return $result
}
function Read-HeldText($held, [string] $label = 'file') {
    Assert-HeldIdentity $held $label; $held.Stream.Position = 0; $reader = New-Object IO.StreamReader($held.Stream,[Text.Encoding]::UTF8,$true,4096,$true)
    try { $result = $reader.ReadToEnd() } finally { $reader.Dispose(); $held.Stream.Position = 0 }; return $result
}
function Close-Held($held) { if ($null -ne $held -and $null -ne $held.Stream) { $held.Stream.Dispose() } }
