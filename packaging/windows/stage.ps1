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
function Get-ExistingOrNewOutput([string] $path) {
    $absolute = Get-Absolute $path 'output'
    if ($absolute -eq [IO.Path]::GetPathRoot($absolute)) { Fail 'refusing a filesystem root as output' }
    if (-not (Test-Path -LiteralPath $absolute)) { New-Item -ItemType Directory -Path $absolute -Force | Out-Null }
    return $absolute
}
function Get-SourceSnapshot([string] $path, [string] $label) {
    $pins = Open-HeldDirectoryPins (Split-Path -Path $path -Parent) $label (Split-Path -Path $path -Parent)
    try { $held = Open-HeldRead $path "$label input" $path }
    catch { Close-Held $pins; throw }
    try { return [pscustomobject]@{ Path=$path; Pins=$pins; Held=$held; Stream=$held.Stream; Hash=(Get-HeldHash $held $label); Length=$held.Stream.Length } }
    catch { Close-Held $held; Close-Held $pins; throw }
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
        $destLength = $stream.Length
        if ($destLength -ne $snapshot.Length) { Fail "$label changed while staging" }
        $stream.Position = 0; $sha = [Security.Cryptography.SHA256]::Create()
        try { $destHash = ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','').ToLowerInvariant() } finally { $sha.Dispose() }
        if ($destHash -cne $snapshot.Hash) { Fail "$label bytes changed while staging" }
        Assert-HeldIdentity $snapshot.Held $label
    } finally { $stream.Dispose() }
}

$resources = New-HeldResourceSet
try {
$scriptRoot = Get-Absolute $PSScriptRoot 'packaging script root'
$gui = Get-Absolute $GuiPath 'GUI'
$helper = Get-Absolute $HelperPath 'helper'
 $outputPin = $null; $outputParentPin = $null; $programFilesPin = $null; $programDataPin = $null; $guiSnapshot = $null; $helperSnapshot = $null
try {
    $outputAbsolute = Get-Absolute $OutputPath 'output'
    $outputParentPath = Split-Path -Path $outputAbsolute -Parent
    $outputParentPin = Open-HeldDirectoryPins $outputParentPath 'stage output parent' $outputParentPath; [void](Add-HeldResource $resources $outputParentPin)
    $output = Get-ExistingOrNewOutput $outputAbsolute
    $outputPin = Open-HeldDirectoryPins $output 'stage output' $output; [void](Add-HeldResource $resources $outputPin)
    if (@(Get-ChildItem -LiteralPath $output -Force).Count -gt 0) { Fail 'output directory must be absent or empty' }
    $programFiles = Join-Path $output 'Program Files\BootHop'; $programData = Join-Path $output 'ProgramData\BootHop'
    New-Item -ItemType Directory -Path $programFiles,$programData -Force | Out-Null
    $programFilesPin = Open-HeldDirectoryPins $programFiles 'Program Files output' $programFiles; [void](Add-HeldResource $resources $programFilesPin)
    $programDataPin = Open-HeldDirectoryPins $programData 'ProgramData output' $programData; [void](Add-HeldResource $resources $programDataPin)
    $guiSnapshot = Get-SourceSnapshot $gui 'GUI'; $helperSnapshot = Get-SourceSnapshot $helper 'helper'
    [void](Add-HeldResource $resources $guiSnapshot.Pins); [void](Add-HeldResource $resources $guiSnapshot.Held)
    [void](Add-HeldResource $resources $helperSnapshot.Pins); [void](Add-HeldResource $resources $helperSnapshot.Held)
    Copy-Snapshot $guiSnapshot (Join-Path $programFiles 'boothop-gui.exe') 'GUI'
    Copy-Snapshot $helperSnapshot (Join-Path $programFiles 'boothop-helper.exe') 'helper'
    foreach ($manifestName in @('boothop-gui.manifest','boothop-helper.manifest')) {
        $source = Get-Absolute (Join-Path $scriptRoot $manifestName) "manifest $manifestName"
        $sourceSnapshot = Get-SourceSnapshot $source "manifest $manifestName"
        [void](Add-HeldResource $resources $sourceSnapshot.Pins); [void](Add-HeldResource $resources $sourceSnapshot.Held)
        try { Copy-Snapshot $sourceSnapshot (Join-Path $programFiles $manifestName) "manifest $manifestName" } finally { Close-Held $sourceSnapshot.Held }
    }
    $policy = [ordered]@{ schema_version=1; path='ProgramData\BootHop'; owner='SYSTEM-or-BUILTIN-Administrators'; ordinary_user_access='none'; acl_enforcement='installer-required; staging-does-not-mutate-ACL'; note='Intent metadata only; staging never creates, changes, or validates a live ACL.' }
    $policy | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $programData '.directory-policy.json') -Encoding UTF8 -NoNewline
    $manifestSource = Get-SourceSnapshot (Get-Absolute (Join-Path $scriptRoot 'manifest.json') 'manifest.json') 'manifest.json'
    [void](Add-HeldResource $resources $manifestSource.Pins); [void](Add-HeldResource $resources $manifestSource.Held)
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
} finally { Close-HeldResourceSet $resources }
