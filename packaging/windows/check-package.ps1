[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [Alias('Stage','Path','RootPath','OutputPath')]
    [string] $StagePath
)

$ErrorActionPreference = 'Stop'
function Fail([string] $message) { throw "Windows package check failed: $message" }

function Get-CanonicalDirectory([string] $path, [string] $label) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)) { Fail "$label must be absolute" }
    $item = Get-Item -LiteralPath ([IO.Path]::GetFullPath($path)) -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or -not $item.PSIsContainer) { Fail "$label is missing or not a directory" }
    $current = $item
    while ($null -ne $current) {
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label contains a reparse point: $($current.FullName)" }
        if ($null -eq $current.Parent -or $current.FullName -eq [IO.Path]::GetPathRoot($current.FullName)) { break }
        $current = Get-Item -LiteralPath $current.Parent.FullName -Force -ErrorAction Stop
    }
    $resolved = (Resolve-Path -LiteralPath $item.FullName -ErrorAction Stop).Path
    if ($resolved -cne $item.FullName) { Fail "$label canonical path changed during resolution" }
    return $item.FullName
}

function Get-CanonicalFile([string] $path, [string] $label) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)) { Fail "$label must be absolute" }
    $item = Get-Item -LiteralPath ([IO.Path]::GetFullPath($path)) -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.PSIsContainer) { Fail "$label is missing or not a regular file" }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label must not be a reparse point" }
    $current = $item
    while ($null -ne $current) {
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label contains a reparse point: $($current.FullName)" }
        if ($null -eq $current.Parent -or $current.FullName -eq [IO.Path]::GetPathRoot($current.FullName)) { break }
        $current = Get-Item -LiteralPath $current.Parent.FullName -Force -ErrorAction Stop
    }
    $resolved = (Resolve-Path -LiteralPath $item.FullName -ErrorAction Stop).Path
    if ($resolved -cne $item.FullName) { Fail "$label canonical path changed during resolution" }
    return $item.FullName
}

function Contains-Exact([object[]] $values, [string] $expected) {
    foreach ($value in $values) { if ([string]$value -ceq $expected) { return $true } }
    return $false
}

function Read-Exact([IO.Stream] $stream, [int] $count, [string] $label) {
    $bytes = New-Object byte[] $count; $offset = 0
    while ($offset -lt $count) {
        $read = $stream.Read($bytes, $offset, $count - $offset)
        if ($read -le 0) { Fail "$label is truncated" }
        $offset += $read
    }
    return $bytes
}

function Assert-Amd64Pe([string] $path, [string] $label) {
    $stream = $null
    try {
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -lt 0x86) { Fail "$label is not an AMD64 PE" }
        $stream.Position = 0; $dos = Read-Exact $stream 64 $label
        if ($dos[0] -ne 0x4d -or $dos[1] -ne 0x5a) { Fail "$label is not an AMD64 PE" }
        $offset = [BitConverter]::ToInt32($dos, 0x3c)
        if ($offset -lt 64 -or $offset -gt $stream.Length - 26) { Fail "$label is not an AMD64 PE" }
        $stream.Position = $offset; $header = Read-Exact $stream 26 $label
        if ($header[0] -ne 0x50 -or $header[1] -ne 0x45 -or $header[2] -ne 0 -or $header[3] -ne 0) { Fail "$label is not an AMD64 PE" }
        $machine = [BitConverter]::ToUInt16($header, 4)
        if ($machine -ne 0x8664) { Fail ("{0} has unsupported PE machine 0x{1:X4}; expected AMD64" -f $label,$machine) }
        if ([BitConverter]::ToUInt16($header, 24) -ne 0x20b) { Fail "$label is not a PE32+ AMD64 image" }
    } finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function Read-ManifestXml([string] $path, [string] $label) {
    $text = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
    try {
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $doc = New-Object System.Xml.XmlDocument
        $doc.PreserveWhitespace = $true
        $reader = [System.Xml.XmlReader]::Create([IO.StringReader]::new($text), $settings)
        try { $doc.Load($reader) } finally { $reader.Dispose() }
    } catch { Fail "$label is not well-formed XML" }
    foreach ($comment in $doc.SelectNodes('//comment()')) {
        if ($comment.Value -match '(?i)requestedExecutionLevel') { Fail "$label contains a requestedExecutionLevel spoof in a comment" }
    }
    return $doc
}

function Assert-ExecutionManifest([string] $path, [string] $label, [string] $expectedLevel) {
    $doc = Read-ManifestXml $path $label
    $nodes = @($doc.SelectNodes("//*[local-name()='requestedExecutionLevel']"))
    if ($nodes.Count -ne 1) { Fail "$label must contain exactly one requestedExecutionLevel" }
    $node = $nodes[0]
    if ($node.Attributes.Count -ne 2) { Fail "$label requestedExecutionLevel attributes are not exact" }
    $level = $node.GetAttribute('level'); $uiAccess = $node.GetAttribute('uiAccess')
    if ($level -cne $expectedLevel -or $uiAccess -cne 'false') { Fail "$label requestedExecutionLevel level/uiAccess is incorrect" }
    foreach ($attribute in $node.Attributes) {
        if ($attribute.Name -cne 'level' -and $attribute.Name -cne 'uiAccess') { Fail "$label requestedExecutionLevel attributes are not exact" }
    }
}

$stage = Get-CanonicalDirectory $StagePath 'stage root'
$required = @('manifest.json','NON-PRODUCTION.txt','Program Files\BootHop\boothop-gui.exe','Program Files\BootHop\boothop-helper.exe','Program Files\BootHop\boothop-gui.manifest','Program Files\BootHop\boothop-helper.manifest','ProgramData\BootHop\.directory-policy.json')
$requiredDirs = @('Program Files','Program Files\BootHop','ProgramData','ProgramData\BootHop')
$actualDirs = @(Get-ChildItem -LiteralPath $stage -Recurse -Directory -Force | ForEach-Object {
    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "reparse-point directory is forbidden: $($_.FullName)" }
    [IO.Path]::GetRelativePath($stage, $_.FullName).Replace('/','\')
}) | Sort-Object
foreach ($name in $requiredDirs) { if (-not (Contains-Exact $actualDirs $name)) { Fail "missing required directory: $name" } }
foreach ($name in $actualDirs) { if (-not (Contains-Exact $requiredDirs $name)) { Fail "unexpected package directory: $name" } }
$actual = @(Get-ChildItem -LiteralPath $stage -Recurse -File -Force | ForEach-Object {
    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "reparse-point file is forbidden: $($_.FullName)" }
    [IO.Path]::GetRelativePath($stage, $_.FullName).Replace('/','\')
}) | Sort-Object
foreach ($name in $required) { if (-not (Contains-Exact $actual $name)) { Fail "missing required file: $name" } }
foreach ($name in $actual) { if (-not (Contains-Exact $required $name)) { Fail "unexpected package file: $name" } }

$manifestPath = Get-CanonicalFile (Join-Path $stage 'manifest.json') 'package manifest'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.product -cne 'BootHop') { Fail 'invalid manifest identity' }
if ($manifest.production_status -cne 'NON-PRODUCTION') { Fail 'missing NON-PRODUCTION status' }
if ($manifest.architecture -cne 'x86_64-pc-windows-msvc') { Fail 'unsupported or missing architecture' }
if ($manifest.protocol_version -ne 2) { Fail 'package protocol must be v2' }
if ($manifest.publisher -cne 'UNSIGNED-DEVELOPMENT-PLACEHOLDER') { Fail 'publisher must remain an explicit placeholder' }
if ($manifest.signing.status -cne 'UNSIGNED-PLACEHOLDER') { Fail 'signing status must remain an explicit placeholder' }
if ($manifest.layout.program_files -cne 'Program Files\BootHop' -or $manifest.layout.program_data -cne 'ProgramData\BootHop' -or $manifest.layout.gui -cne 'Program Files\BootHop\boothop-gui.exe' -or $manifest.layout.helper -cne 'Program Files\BootHop\boothop-helper.exe' -or $manifest.layout.record -cne 'ProgramData\BootHop\targets.json') { Fail 'fixed layout metadata is incorrect' }
if ($manifest.binaries.gui.protocol_version -ne 2 -or $manifest.binaries.helper.protocol_version -ne 2) { Fail 'mixed binary protocol metadata' }
if ($manifest.binaries.gui.execution_level -cne 'asInvoker' -or $manifest.binaries.helper.execution_level -cne 'requireAdministrator') { Fail 'binary execution level metadata is incorrect' }
if ($manifest.binaries.gui.path -cne 'Program Files\BootHop\boothop-gui.exe' -or $manifest.binaries.helper.path -cne 'Program Files\BootHop\boothop-helper.exe') { Fail 'binary paths must remain fixed and package-local' }
if ($manifest.program_data_policy.directory -cne 'ProgramData\BootHop' -or $manifest.program_data_policy.owner -cne 'SYSTEM-or-BUILTIN-Administrators' -or $manifest.program_data_policy.ordinary_user_access -cne 'none') { Fail 'ProgramData policy metadata is incorrect' }
$gui = Get-CanonicalFile (Join-Path $stage 'Program Files\BootHop\boothop-gui.exe') 'staged GUI PE'
$helper = Get-CanonicalFile (Join-Path $stage 'Program Files\BootHop\boothop-helper.exe') 'staged helper PE'
$guiBefore = Get-Item -LiteralPath $gui -Force; $helperBefore = Get-Item -LiteralPath $helper -Force
Assert-Amd64Pe $gui 'GUI PE'; Assert-Amd64Pe $helper 'helper PE'
foreach ($pair in @(@($gui,$manifest.binaries.gui.sha256,'GUI',$manifest.binaries.gui.size,$guiBefore),@($helper,$manifest.binaries.helper.sha256,'helper',$manifest.binaries.helper.size,$helperBefore))) {
    if ([string]$pair[1] -cnotmatch '^[0-9a-f]{64}$') { Fail "$($pair[2]) hash is absent or malformed" }
    if ([int64]$pair[3] -ne [int64]$pair[4].Length) { Fail "$($pair[2]) size does not match staged bytes" }
    $stream = [IO.File]::Open($pair[0],[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read); $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','').ToLowerInvariant() } finally { $sha.Dispose(); $stream.Dispose() }
    if ($hash -cne [string]$pair[1]) { Fail "$($pair[2]) hash does not match staged bytes" }
    $after = Get-Item -LiteralPath $pair[0] -Force
    if ($after.Length -ne $pair[4].Length -or $after.LastWriteTimeUtc -ne $pair[4].LastWriteTimeUtc -or $after.Attributes -ne $pair[4].Attributes -or $after.FullName -cne $pair[4].FullName) { Fail "$($pair[2]) changed during package check" }
}
Assert-ExecutionManifest (Join-Path $stage 'Program Files\BootHop\boothop-gui.manifest') 'GUI manifest' 'asInvoker'
Assert-ExecutionManifest (Join-Path $stage 'Program Files\BootHop\boothop-helper.manifest') 'helper manifest' 'requireAdministrator'
$policy = Get-Content -LiteralPath (Join-Path $stage 'ProgramData\BootHop\.directory-policy.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($policy.schema_version -ne 1 -or $policy.path -cne 'ProgramData\BootHop' -or $policy.owner -cne 'SYSTEM-or-BUILTIN-Administrators' -or $policy.ordinary_user_access -cne 'none') { Fail 'ProgramData policy metadata is incorrect' }
if ((Get-Content -LiteralPath (Join-Path $stage 'NON-PRODUCTION.txt') -Raw) -notmatch '(?i)installer.*recovery|recovery.*downgrade') { Fail 'non-production marker is incomplete' }
Write-Output 'Windows package check: passed'
