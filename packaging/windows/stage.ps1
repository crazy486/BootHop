[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)] [Alias('Gui','ReleaseGui','GuiBinary','GuiInput','ReleaseGuiPath')] [string] $GuiPath,
    [Parameter(Mandatory=$true, Position=1)] [Alias('Helper','ReleaseHelper','HelperBinary','HelperInput','ReleaseHelperPath')] [string] $HelperPath,
    [Parameter(Mandatory=$true, Position=2)] [Alias('Output','Stage','StagePath','OutputDir','Destination')] [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'held.ps1')
function Fail([string] $message) { throw "Windows package staging failed: $message" }
function Get-Absolute([string] $path, [string] $label) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)) { Fail "$label must be an absolute path" }
    try { return [IO.Path]::GetFullPath($path) } catch { Fail "$label is not a valid path" }
}
function Assert-NoReparseAncestors([string] $path, [string] $label) {
    $currentPath = [IO.Path]::GetFullPath($path)
    while ($true) {
        $current = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label contains a reparse point: $($current.FullName)" }
        $parent = Split-Path -Path $currentPath -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $currentPath -or $currentPath -eq [IO.Path]::GetPathRoot($currentPath)) { break }
        $currentPath = $parent
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
    $held = Open-HeldRead $path $label $path
    try { return [pscustomobject]@{ Path=$path; Held=$held; Stream=$held.Stream; Hash=(Get-HeldHash $held $label); Length=$held.Stream.Length } }
    catch { Close-Held $held; throw }
}
function Copy-Snapshot($snapshot, [string] $destination, [string] $label) {
    $destination = Get-Absolute $destination 'staged output'
    $stream = [IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $snapshot.Stream.Position = 0
        $snapshot.Stream.CopyTo($stream); $stream.Flush($true)
        Assert-HeldIdentity $snapshot.Held $label
        $destIdentity = [WindowsFileHandle]::Identity($stream.SafeFileHandle)
        $destFinal = Normalize-HeldPath (($destIdentity -split '\|')[0])
        if ($destFinal -cne $destination) { Fail "$label output canonical path changed while staging" }
        Assert-NoReparseAncestors $destination "$label output"
        $destLength = $stream.Length
        if ($destLength -ne $snapshot.Length) { Fail "$label changed while staging" }
        $stream.Position = 0; $sha = [Security.Cryptography.SHA256]::Create()
        try { $destHash = ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','').ToLowerInvariant() } finally { $sha.Dispose() }
        if ($destHash -cne $snapshot.Hash) { Fail "$label bytes changed while staging" }
        Assert-HeldIdentity $snapshot.Held $label
    } finally { $stream.Dispose() }
}

$scriptRoot = (Resolve-Path $PSScriptRoot).Path
Assert-NoReparseAncestors $scriptRoot 'packaging script root'
$gui = Get-CanonicalFile $GuiPath 'GUI'
$helper = Get-CanonicalFile $HelperPath 'helper'
$output = Get-ExistingOrNewOutput $OutputPath
$programFiles = Join-Path $output 'Program Files\BootHop'; $programData = Join-Path $output 'ProgramData\BootHop'
New-Item -ItemType Directory -Path $programFiles,$programData -Force | Out-Null
Assert-NoReparseAncestors $programFiles 'Program Files output'; Assert-NoReparseAncestors $programData 'ProgramData output'
 $outputPin = $null; $outputParentPin = $null; $programFilesPin = $null; $programDataPin = $null; $guiSnapshot = $null; $helperSnapshot = $null
try {
    $outputPin = Open-HeldDirectory $output 'stage output' $output
    $outputParentPin = Open-HeldDirectory (Split-Path -Path $output -Parent) 'stage output parent' (Split-Path -Path $output -Parent)
    $programFilesPin = Open-HeldDirectory $programFiles 'Program Files output' $programFiles
    $programDataPin = Open-HeldDirectory $programData 'ProgramData output' $programData
    $guiSnapshot = Get-SourceSnapshot $gui 'GUI'; $helperSnapshot = Get-SourceSnapshot $helper 'helper'
    Copy-Snapshot $guiSnapshot (Join-Path $programFiles 'boothop-gui.exe') 'GUI'
    Copy-Snapshot $helperSnapshot (Join-Path $programFiles 'boothop-helper.exe') 'helper'
    foreach ($manifestName in @('boothop-gui.manifest','boothop-helper.manifest')) {
        $source = Get-CanonicalFile (Join-Path $scriptRoot $manifestName) "manifest $manifestName"
        $sourceSnapshot = Get-SourceSnapshot $source "manifest $manifestName"
        try { Copy-Snapshot $sourceSnapshot (Join-Path $programFiles $manifestName) "manifest $manifestName" } finally { Close-Held $sourceSnapshot.Held }
    }
    $policy = [ordered]@{ schema_version=1; path='ProgramData\BootHop'; owner='SYSTEM-or-BUILTIN-Administrators'; ordinary_user_access='none'; acl_enforcement='installer-required; staging-does-not-mutate-ACL'; note='Intent metadata only; staging never creates, changes, or validates a live ACL.' }
    $policy | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $programData '.directory-policy.json') -Encoding UTF8 -NoNewline
    $manifestSource = Get-SourceSnapshot (Get-CanonicalFile (Join-Path $scriptRoot 'manifest.json') 'manifest.json') 'manifest.json'
    try { $manifest = Read-HeldText $manifestSource.Held 'manifest.json' | ConvertFrom-Json } finally { Close-Held $manifestSource.Held }
    $manifest.binaries.gui.sha256 = (Get-HeldHash $guiSnapshot.Held 'GUI').ToLowerInvariant()
    $manifest.binaries.helper.sha256 = (Get-HeldHash $helperSnapshot.Held 'helper').ToLowerInvariant()
    $manifest.binaries.gui.size = $guiSnapshot.Length
    $manifest.binaries.helper.size = $helperSnapshot.Length
    Close-Held $guiSnapshot.Held; Close-Held $helperSnapshot.Held
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
} finally {
    Close-Held $guiSnapshot.Held; Close-Held $helperSnapshot.Held
    Close-Held $programFilesPin; Close-Held $programDataPin; Close-Held $outputPin; Close-Held $outputParentPin
}
Write-Output $output
