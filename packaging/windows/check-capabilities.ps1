[CmdletBinding()]
param(
    [Alias('Root','SourceRoot')]
    [string] $RootPath = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [Parameter(Mandatory=$true)] [Alias('Gui','GuiPe')] [string] $GuiPath,
    [Parameter(Mandatory=$true)] [Alias('Helper','HelperPe')] [string] $HelperPath,
    [Parameter(Mandatory=$true)] [Alias('Dumpbin','DumpbinExe')] [string] $DumpbinPath,
    # This seam is intentionally unavailable to the production CI invocation.
    # It exists only so package_fake.ps1 can exercise parser failure cases without
    # executing a real PE or pretending a .ps1 is Visual Studio dumpbin.exe.
    [switch] $TestOnlyFixtureMode
)

$ErrorActionPreference = 'Stop'
function Fail([string] $message) { throw "Windows capability audit failed: $message" }

function Get-Absolute([string] $path, [string] $label) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)) { Fail "$label must be an absolute path" }
    try { return [IO.Path]::GetFullPath($path) } catch { Fail "$label is not a valid path" }
}

function Assert-NoReparseAncestors([string] $path, [string] $label) {
    $current = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    while ($null -ne $current) {
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label contains a reparse point: $($current.FullName)" }
        if ($null -eq $current.Parent -or $current.FullName -eq [IO.Path]::GetPathRoot($current.FullName)) { break }
        $current = Get-Item -LiteralPath $current.Parent.FullName -Force -ErrorAction Stop
    }
}

function Get-CanonicalDirectory([string] $path, [string] $label) {
    $absolute = Get-Absolute $path $label
    $item = Get-Item -LiteralPath $absolute -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or -not $item.PSIsContainer) { Fail "$label is missing or not a directory" }
    Assert-NoReparseAncestors $absolute $label
    $resolved = (Resolve-Path -LiteralPath $absolute -ErrorAction Stop).Path
    if ($resolved -cne $item.FullName) { Fail "$label canonical path changed during resolution" }
    return $item.FullName
}

function Get-CanonicalFile([string] $path, [string] $label) {
    $absolute = Get-Absolute $path $label
    $item = Get-Item -LiteralPath $absolute -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.PSIsContainer) { Fail "$label is missing or not a regular file" }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label must not be a reparse point" }
    Assert-NoReparseAncestors $absolute $label
    $resolved = (Resolve-Path -LiteralPath $absolute -ErrorAction Stop).Path
    if ($resolved -cne $item.FullName) { Fail "$label canonical path changed during resolution" }
    return $item.FullName
}

function Assert-Contained([string] $root, [string] $path, [string] $label) {
    $relative = [IO.Path]::GetRelativePath($root, $path)
    if ([IO.Path]::IsPathRooted($relative) -or $relative -eq '..' -or $relative.StartsWith('..\') -or $relative.StartsWith('../')) { Fail "$label escapes the source root" }
}

$root = Get-CanonicalDirectory $RootPath 'source root'
$dumpbin = Get-CanonicalFile $DumpbinPath 'dumpbin'
if ($TestOnlyFixtureMode) {
    if ([IO.Path]::GetExtension($dumpbin) -cne '.ps1') { Fail 'test-only dumpbin must be a .ps1 fixture' }
} elseif ([IO.Path]::GetFileName($dumpbin) -cne 'dumpbin.exe') {
    Fail 'production dumpbin must be canonical dumpbin.exe'
}
$guiPath = Get-CanonicalFile $GuiPath 'GUI PE'
$helperPath = Get-CanonicalFile $HelperPath 'helper PE'

function Read-Exact([IO.Stream] $stream, [int] $count, [string] $label) {
    $bytes = New-Object byte[] $count; $offset = 0
    while ($offset -lt $count) {
        $read = $stream.Read($bytes, $offset, $count - $offset)
        if ($read -le 0) { Fail "$label is truncated" }
        $offset += $read
    }
    return $bytes
}

function Get-PeSnapshot([string] $path, [string] $label) {
    $before = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    $stream = $null; $sha = $null
    try {
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $length = $stream.Length
        if ($length -lt 0x86) { Fail "$label is not a PE: file is too small" }
        $stream.Position = 0; $dos = Read-Exact $stream 64 $label
        if ($dos[0] -ne 0x4d -or $dos[1] -ne 0x5a) { Fail "$label is not a PE: missing MZ header" }
        $peOffset = [BitConverter]::ToInt32($dos, 0x3c)
        if ($peOffset -lt 64 -or $peOffset -gt $length - 24) { Fail "$label is not a PE: invalid header offset" }
        $stream.Position = $peOffset; $header = Read-Exact $stream 26 $label
        if ($header[0] -ne 0x50 -or $header[1] -ne 0x45 -or $header[2] -ne 0 -or $header[3] -ne 0) { Fail "$label is not a PE: missing signature" }
        $machine = [BitConverter]::ToUInt16($header, 4)
        if ($machine -ne 0x8664) { Fail ("{0} has unsupported PE machine 0x{1:X4}; expected AMD64" -f $label,$machine) }
        $optionalMagic = [BitConverter]::ToUInt16($header, 24)
        if ($optionalMagic -ne 0x20b) { Fail "$label is not a PE32+ AMD64 image" }
        $stream.Position = 0; $sha = [Security.Cryptography.SHA256]::Create()
        $digest = $sha.ComputeHash($stream)
        $hash = ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
    } finally {
        if ($null -ne $sha) { $sha.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $after = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($before.Length -ne $after.Length -or $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc -or $before.Attributes -ne $after.Attributes -or $before.FullName -cne $after.FullName) { Fail "$label changed during PE inspection" }
    return [pscustomobject]@{ Path = $path; Hash = $hash; Length = $length }
}

$guiPe = Get-PeSnapshot $guiPath 'GUI PE'; $helperPe = Get-PeSnapshot $helperPath 'helper PE'

# Complete production source/generated input scope. Every root must exist and
# contain a file; otherwise an audit could pass vacuously.
$sourceSpecs = @(
    @{ Relative = 'crates\core\src'; Directory = $true },
    @{ Relative = 'crates\gui\src'; Directory = $true },
    @{ Relative = 'crates\gui\ui'; Directory = $true },
    @{ Relative = 'crates\gui\build.rs'; Directory = $false },
    @{ Relative = 'crates\helper\src'; Directory = $true },
    @{ Relative = 'crates\platform\src'; Directory = $true },
    @{ Relative = 'crates\protocol\src'; Directory = $true }
)
$sourceFiles = [Collections.Generic.List[object]]::new()
foreach ($spec in $sourceSpecs) {
    $candidate = Join-Path $root $spec.Relative
    if ($spec.Directory) {
        $dir = Get-CanonicalDirectory $candidate "source root $($spec.Relative)"; Assert-Contained $root $dir "source root $($spec.Relative)"
        $entries = @(Get-ChildItem -LiteralPath $dir -Recurse -Force -ErrorAction Stop)
        if (@($entries | Where-Object { -not $_.PSIsContainer }).Count -eq 0) { Fail "source root is empty: $($spec.Relative)" }
        foreach ($entry in $entries) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "source root contains a reparse point: $($entry.FullName)" }
            if (-not $entry.PSIsContainer) { $sourceFiles.Add($entry) }
        }
    } else {
        $file = Get-CanonicalFile $candidate "source input $($spec.Relative)"; Assert-Contained $root $file "source input $($spec.Relative)"
        if ((Get-Item -LiteralPath $file).Length -eq 0) { Fail "source input is empty: $($spec.Relative)" }
        $sourceFiles.Add((Get-Item -LiteralPath $file -Force))
    }
}

$allow = @{
    'SetFirmwareEnvironmentVariable' = @('crates\platform\src\windows\firmware.rs')
    'GetFirmwareEnvironmentVariable' = @('crates\platform\src\windows\firmware.rs')
    'GetFirmwareType' = @('crates\platform\src\windows\firmware.rs')
    'AdjustTokenPrivileges' = @('crates\platform\src\windows\privilege.rs')
    'OpenProcessToken' = @('crates\platform\src\windows\privilege.rs','crates\gui\src\helper_client\windows\native.rs','crates\helper\src\windows\pipe.rs')
    'InitiateSystemShutdown' = @('crates\platform\src\windows\reboot.rs')
    'ExitWindows' = @('crates\platform\src\windows\reboot.rs')
    'ShellExecute' = @('crates\gui\src\helper_client\windows\native.rs')
    'CreateProcess' = @('crates\gui\src\helper_client\windows\native.rs')
}
$patterns = @('SetFirmwareEnvironmentVariable','GetFirmwareEnvironmentVariable','GetFirmwareType','AdjustTokenPrivileges','OpenProcessToken','InitiateSystemShutdown','ExitWindows','ShellExecute','CreateProcess','LoadLibrary','GetProcAddress','bcdedit')
foreach ($file in $sourceFiles) {
    $canonicalFile = Get-CanonicalFile $file.FullName 'source file'; $relative = [IO.Path]::GetRelativePath($root, $canonicalFile).Replace('/','\')
    $text = Get-Content -LiteralPath $canonicalFile -Raw -ErrorAction Stop
    foreach ($pattern in $patterns) {
        if ($text.IndexOf($pattern, [StringComparison]::Ordinal) -lt 0) { continue }
        $allowed = $false
        if ($allow.ContainsKey($pattern)) { foreach ($expected in $allow[$pattern]) { if ($relative -ceq $expected) { $allowed = $true; break } } }
        if (-not $allowed) { Fail "source capability '$pattern' outside its allowlist: $relative" }
    }
}

function Invoke-Dumpbin([string] $path, [string] $label) {
    $dumpbinIdentity = Get-Item -LiteralPath $dumpbin -Force -ErrorAction Stop
    try { $output = @(& $dumpbin /imports $path 2>&1); $exitCode = $LASTEXITCODE } catch { Fail "dumpbin failed for $label" }
    if ($null -eq $exitCode -or $exitCode -ne 0 -or -not $?) { Fail "dumpbin failed for $label" }
    if ($output.Count -eq 0) { Fail "dumpbin output is empty for $label" }
    $after = Get-Item -LiteralPath $dumpbin -Force -ErrorAction Stop
    if ($after.Length -ne $dumpbinIdentity.Length -or $after.LastWriteTimeUtc -ne $dumpbinIdentity.LastWriteTimeUtc -or $after.Attributes -ne $dumpbinIdentity.Attributes -or $after.FullName -cne $dumpbinIdentity.FullName) { Fail 'dumpbin changed during audit' }
    return ($output -join "`n")
}

function Parse-DumpbinImports([string] $text, [string] $label) {
    if ($text -match '(?i)\bordinal\b') { Fail "ordinal import is unsupported for $label" }
    $lines = $text -split "`r?`n"; $inImports = $false; $currentDll = $false; $currentDllNames = 0; $names = [Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line -match '(?i)Section contains the following imports:') { $inImports = $true; continue }
        if (-not $inImports -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*Summary\s*$') { break }
        if ($line -match '^\s+[A-Za-z0-9_.-]+\.dll\s*$') {
            if ($currentDll -and $currentDllNames -eq 0) { Fail "ordinal import is unsupported for $label" }
            $currentDll = $true; $currentDllNames = 0; continue
        }
        if ($line -match '^\s*[0-9A-Fa-f]{8,16}\s+(Import Address Table|Import Name Table)$' -or $line -match '^\s*[0-9A-Fa-f]+\s+(time date stamp|Index of first forwarder reference)$' -or $line -match '^\s*(?:[0-9A-Fa-f]+\s+){4,}[0-9A-Fa-f]+\s*$') { continue }
        if ($line -match '^\s*[0-9A-Fa-f]{1,16}\s+([A-Za-z_?$@][A-Za-z0-9_?$@.\-]*)\s*$') {
            if (-not $currentDll) { Fail "unrecognized import form for $label" }
            $names.Add($Matches[1]); $currentDllNames++; continue
        }
        Fail "unrecognized import form for $label"
    }
    if (-not $inImports) { Fail "unrecognized dumpbin output for $label" }
    if ($currentDll -and $currentDllNames -eq 0) { Fail "ordinal import is unsupported for $label" }
    return @($names)
}

$guiImports = Parse-DumpbinImports (Invoke-Dumpbin $guiPath 'GUI PE') 'GUI PE'; $helperImports = Parse-DumpbinImports (Invoke-Dumpbin $helperPath 'helper PE') 'helper PE'
$guiForbidden = 'SetFirmwareEnvironmentVariable|GetFirmwareEnvironmentVariable|AdjustTokenPrivileges|OpenProcessToken|InitiateSystemShutdown|ExitWindows|LoadLibrary|GetProcAddress|bcdedit'
$helperForbidden = 'SetFirmwareEnvironmentVariable|GetFirmwareEnvironmentVariable|AdjustTokenPrivileges|OpenProcessToken|InitiateSystemShutdown|ExitWindows|LoadLibrary|GetProcAddress|bcdedit|CreateProcess|ShellExecute'
if (($guiImports | Where-Object { $_ -match $guiForbidden }).Count -gt 0) { Fail 'GUI PE imports a forbidden capability' }
if (($helperImports | Where-Object { $_ -match $helperForbidden }).Count -gt 0) { Fail 'helper PE imports a forbidden capability' }
foreach ($pe in @($guiPe,$helperPe)) { if ((Get-FileHash -LiteralPath $pe.Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pe.Hash) { Fail "PE changed during dumpbin audit: $($pe.Path)" } }
Write-Output 'Windows source and PE capability audit: passed'
