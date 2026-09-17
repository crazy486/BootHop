[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)] [Alias('Gui','ReleaseGui','GuiBinary','GuiInput','ReleaseGuiPath')] [string] $GuiPath,
    [Parameter(Mandatory=$true, Position=1)] [Alias('Helper','ReleaseHelper','HelperBinary','HelperInput','ReleaseHelperPath')] [string] $HelperPath,
    [Parameter(Mandatory=$true, Position=2)] [Alias('Output','Stage','StagePath','OutputDir','Destination')] [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
function Fail([string] $message) { throw "Windows package staging failed: $message" }
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
function Get-CanonicalFile([string] $path, [string] $label) {
    $absolute = Get-Absolute $path $label
    $item = Get-Item -LiteralPath $absolute -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.PSIsContainer) { Fail "$label input is missing or not a regular file" }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label input must not be a reparse point" }
    Assert-NoReparseAncestors $absolute $label
    $resolved = (Resolve-Path -LiteralPath $absolute -ErrorAction Stop).Path
    if ($resolved -cne $item.FullName) { Fail "$label input canonical path changed during resolution" }
    return $item.FullName
}
function Get-ExistingOrNewOutput([string] $path) {
    $absolute = Get-Absolute $path 'output'
    $probe = $absolute
    while ($true) {
        if (Test-Path -LiteralPath $probe) {
            Assert-NoReparseAncestors $probe 'output'
            break
        }
        $parent = Split-Path -Path $probe -Parent
        if ($parent -eq $probe -or [string]::IsNullOrWhiteSpace($parent)) { break }
        $probe = $parent
    }
    if ($absolute -eq [IO.Path]::GetPathRoot($absolute)) { Fail 'refusing a filesystem root as output' }
    if (Test-Path -LiteralPath $absolute) {
        $item = Get-Item -LiteralPath $absolute -Force -ErrorAction Stop
        if (-not $item.PSIsContainer) { Fail 'output must be a directory' }
        if (@(Get-ChildItem -LiteralPath $absolute -Force).Count -gt 0) { Fail 'output directory must be absent or empty' }
    } else { New-Item -ItemType Directory -Path $absolute -Force | Out-Null }
    Assert-NoReparseAncestors $absolute 'output'
    return (Get-Item -LiteralPath $absolute -Force).FullName
}
function Get-SourceSnapshot([string] $path, [string] $label) {
    $before = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','').ToLowerInvariant() } finally { $sha.Dispose() }
        $stream.Position = 0
        return [pscustomobject]@{ Path=$path; Stream=$stream; Hash=$hash; Length=$before.Length; LastWrite=$before.LastWriteTimeUtc; Attributes=$before.Attributes; FullName=$before.FullName }
    } catch { $stream.Dispose(); throw }
}
function Copy-Snapshot($snapshot, [string] $destination, [string] $label) {
    $destination = Get-Absolute $destination 'staged output'
    $stream = [IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $snapshot.Stream.CopyTo($stream); $stream.Flush($true) } finally { $stream.Dispose() }
    $destItem = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
    if ($destItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label output is a reparse point" }
    Assert-NoReparseAncestors $destination "$label output"
    if ((Resolve-Path -LiteralPath $destination -ErrorAction Stop).Path -cne $destItem.FullName) { Fail "$label output canonical path changed while staging" }
    if ($destItem.Length -ne $snapshot.Length) { Fail "$label changed while staging" }
    $destHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($destHash -cne $snapshot.Hash) { Fail "$label bytes changed while staging" }
    $sourceAfter = Get-Item -LiteralPath $snapshot.Path -Force -ErrorAction Stop
    if ($sourceAfter.Length -ne $snapshot.Length -or $sourceAfter.LastWriteTimeUtc -ne $snapshot.LastWrite -or $sourceAfter.Attributes -ne $snapshot.Attributes -or $sourceAfter.FullName -cne $snapshot.FullName) { Fail "$label input changed while staging" }
}

$scriptRoot = (Resolve-Path $PSScriptRoot).Path
Assert-NoReparseAncestors $scriptRoot 'packaging script root'
$gui = Get-CanonicalFile $GuiPath 'GUI'
$helper = Get-CanonicalFile $HelperPath 'helper'
$output = Get-ExistingOrNewOutput $OutputPath
$programFiles = Join-Path $output 'Program Files\BootHop'; $programData = Join-Path $output 'ProgramData\BootHop'
New-Item -ItemType Directory -Path $programFiles,$programData -Force | Out-Null
Assert-NoReparseAncestors $programFiles 'Program Files output'; Assert-NoReparseAncestors $programData 'ProgramData output'
$guiSnapshot = Get-SourceSnapshot $gui 'GUI'; $helperSnapshot = Get-SourceSnapshot $helper 'helper'
try {
    Copy-Snapshot $guiSnapshot (Join-Path $programFiles 'boothop-gui.exe') 'GUI'
    Copy-Snapshot $helperSnapshot (Join-Path $programFiles 'boothop-helper.exe') 'helper'
} finally { $guiSnapshot.Stream.Dispose(); $helperSnapshot.Stream.Dispose() }
foreach ($manifest in @('boothop-gui.manifest','boothop-helper.manifest')) {
    $source = Get-CanonicalFile (Join-Path $scriptRoot $manifest) "manifest $manifest"
    Copy-Item -LiteralPath $source -Destination (Join-Path $programFiles $manifest) -Force
}
$policy = [ordered]@{ schema_version=1; path='ProgramData\BootHop'; owner='SYSTEM-or-BUILTIN-Administrators'; ordinary_user_access='none'; note='Intent metadata only; staging never creates, changes, or validates a live ACL.' }
$policy | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $programData '.directory-policy.json') -Encoding UTF8 -NoNewline
$manifest = Get-Content -LiteralPath (Join-Path $scriptRoot 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$manifest.binaries.gui.sha256 = (Get-FileHash -LiteralPath (Join-Path $programFiles 'boothop-gui.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest.binaries.helper.sha256 = (Get-FileHash -LiteralPath (Join-Path $programFiles 'boothop-helper.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest.binaries.gui.size = (Get-Item -LiteralPath (Join-Path $programFiles 'boothop-gui.exe')).Length
$manifest.binaries.helper.size = (Get-Item -LiteralPath (Join-Path $programFiles 'boothop-helper.exe')).Length
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding UTF8 -NoNewline
@'
BootHop Windows package staging marker
status=NON-PRODUCTION
This is a deterministic, non-installing package stage only.
Production release is blocked until an atomic installer, interrupted-upgrade recovery,
downgrade prevention, and code-signing/release process are implemented and verified.
No service, autostart, driver, BCD, ACL mutation, UAC, helper execution, firmware call,
shutdown, or reboot is performed by this stage.
'@ | Set-Content -LiteralPath (Join-Path $output 'NON-PRODUCTION.txt') -Encoding UTF8 -NoNewline
Write-Output $output
