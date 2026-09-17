[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [Alias('Stage','Path','RootPath','OutputPath')]
    [string] $StagePath
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'held.ps1')
function Close-PackageHandles {
    Close-HeldResourceSet $resources
}
function Fail([string] $message) { Close-PackageHandles; throw "Windows package check failed: $message" }

function Get-AbsoluteDirectory([string] $path, [string] $label) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)) { Fail "$label must be absolute" }
    return [IO.Path]::GetFullPath($path)
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

function Assert-Amd64Pe($held, [string] $label) {
    Assert-HeldIdentity $held $label
    $stream = $held.Stream
    try {
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
    } finally { if (-not $stream.SafeFileHandle.IsClosed) { $stream.Position = 0 } }
    Assert-HeldIdentity $held $label
}

function Read-ManifestXml($held, [string] $label) {
    $text = Read-HeldText $held $label
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

function Assert-ExecutionManifest($held, [string] $label, [string] $expectedLevel) {
    $doc = Read-ManifestXml $held $label
    $nodes = @($doc.SelectNodes("//*[local-name()='requestedExecutionLevel']"))
    if ($nodes.Count -ne 1) { Fail "$label must contain exactly one requestedExecutionLevel" }
    $root = $doc.DocumentElement
    if ($null -eq $root -or $root.LocalName -cne 'assembly' -or $root.NamespaceURI -cne 'urn:schemas-microsoft-com:asm.v1') { Fail "$label root must be assembly in the asm.v1 namespace" }
    $rootElements = @($root.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
    if ($rootElements.Count -ne 3) { Fail "$label document hierarchy is not exact" }
    $identity = @($rootElements | Where-Object { $_.LocalName -ceq 'assemblyIdentity' -and $_.NamespaceURI -ceq 'urn:schemas-microsoft-com:asm.v1' })
    $description = @($rootElements | Where-Object { $_.LocalName -ceq 'description' -and $_.NamespaceURI -ceq 'urn:schemas-microsoft-com:asm.v1' })
    $trustInfo = @($rootElements | Where-Object { $_.LocalName -ceq 'trustInfo' -and $_.NamespaceURI -ceq 'urn:schemas-microsoft-com:asm.v3' })
    if ($identity.Count -ne 1 -or $description.Count -ne 1 -or $trustInfo.Count -ne 1) { Fail "$label document hierarchy or namespace is not exact" }
    $trustNode = $trustInfo | Select-Object -First 1
    $security = if ($null -ne $trustNode) { [object[]]@($trustNode.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }) } else { [object[]]@() }
    $security = [object[]]$security
    $securityNode = $security | Select-Object -First 1
    $privileges = if ($security.Count -eq 1) { [object[]]@($securityNode.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }) } else { [object[]]@() }
    $privileges = [object[]]$privileges
    $privilegesNode = $privileges | Select-Object -First 1
    $execParents = if ($privileges.Count -eq 1) { [object[]]@($privilegesNode.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }) } else { [object[]]@() }
    $execParents = [object[]]$execParents
    $execNode = $execParents | Select-Object -First 1
    if ($securityNode) { $security = @(,$securityNode) }
    if ($privilegesNode) { $privileges = @(,$privilegesNode) }
    if ($execNode) { $execParents = @(,$execNode) }
    $securityElements = if ($trustInfo.Count -eq 1) { @($trustNode.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }) } else { @() }
    $securityElement = $securityElements | Select-Object -First 1
    $privilegeElements = if ($securityElements.Count -eq 1) { @($securityElement.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }) } else { @() }
    $privilegeElement = $privilegeElements | Select-Object -First 1
    $executionElements = if ($privilegeElements.Count -eq 1) { @($privilegeElement.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }) } else { @() }
    if ($securityElements.Count -ne 1 -or $privilegeElements.Count -ne 1 -or $executionElements.Count -ne 1) { Fail "$label document hierarchy is not exact" }
    if ($security.Count -ne 1 -or $security[0].LocalName -cne 'security' -or $security[0].NamespaceURI -cne 'urn:schemas-microsoft-com:asm.v3' -or $privileges.Count -ne 1 -or $privileges[0].LocalName -cne 'requestedPrivileges' -or $privileges[0].NamespaceURI -cne 'urn:schemas-microsoft-com:asm.v3' -or $execParents.Count -ne 1 -or $execParents[0].LocalName -cne 'requestedExecutionLevel' -or $execParents[0].NamespaceURI -ne 'urn:schemas-microsoft-com:asm.v3') { Fail "$label document hierarchy or namespace is not exact" }
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

$resources = New-HeldResourceSet
try {
$stage = Get-AbsoluteDirectory $StagePath 'stage root'
$stageParent = Split-Path -Path $stage -Parent
$stagePin = Open-HeldDirectoryPins $stage 'stage root' $stage; [void](Add-HeldResource $resources $stagePin)
$stage = $stagePin.Canonical
$stageParentPin = Open-HeldDirectoryPins $stageParent 'stage parent' $stageParent; [void](Add-HeldResource $resources $stageParentPin)
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

$manifestPath = [IO.Path]::GetFullPath((Join-Path $stage 'manifest.json'))
$manifestResource = Open-HeldFileResource $manifestPath 'package manifest' $manifestPath; [void](Add-HeldResource $resources $manifestResource)
$manifestHeld = $manifestResource.Held
$manifest = Read-HeldText $manifestHeld 'package manifest' | ConvertFrom-Json
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
if ($manifest.program_data_policy.directory -cne 'ProgramData\BootHop' -or $manifest.program_data_policy.owner -cne 'SYSTEM-or-BUILTIN-Administrators' -or $manifest.program_data_policy.ordinary_user_access -cne 'none' -or $manifest.program_data_policy.acl_enforcement -cne 'installer-required; staging-does-not-mutate-ACL') { Fail 'ProgramData policy metadata is incorrect' }

$expectedForbidden = @('service','scheduled-task','run-key','startup-shortcut','driver','bcdedit','shell-command-handler')
if ($null -eq $manifest.forbidden_artifacts -or @($manifest.forbidden_artifacts).Count -ne $expectedForbidden.Count) { Fail 'forbidden artifact policy is incorrect' }
for ($index = 0; $index -lt $expectedForbidden.Count; $index++) { if ([string]$manifest.forbidden_artifacts[$index] -cne $expectedForbidden[$index]) { Fail 'forbidden artifact policy is incorrect' } }
$gui = [IO.Path]::GetFullPath((Join-Path $stage 'Program Files\BootHop\boothop-gui.exe'))
$helper = [IO.Path]::GetFullPath((Join-Path $stage 'Program Files\BootHop\boothop-helper.exe'))
$guiResource = Open-HeldFileResource $gui 'GUI PE' $gui; [void](Add-HeldResource $resources $guiResource); $guiHeld = $guiResource.Held
$helperResource = Open-HeldFileResource $helper 'helper PE' $helper; [void](Add-HeldResource $resources $helperResource); $helperHeld = $helperResource.Held
Assert-Amd64Pe $guiHeld 'GUI PE'; Assert-Amd64Pe $helperHeld 'helper PE'
foreach ($pair in @(@($guiHeld,$manifest.binaries.gui.sha256,'GUI',$manifest.binaries.gui.size),@($helperHeld,$manifest.binaries.helper.sha256,'helper',$manifest.binaries.helper.size))) {
    if ([string]$pair[1] -cnotmatch '^[0-9a-f]{64}$') { Fail "$($pair[2]) hash is absent or malformed" }
    if ([int64]$pair[3] -ne [int64]$pair[0].Stream.Length) { Fail "$($pair[2]) size does not match staged bytes" }
    $hash = Get-HeldHash $pair[0] $pair[2]
    if ($hash -cne [string]$pair[1]) { Fail "$($pair[2]) hash does not match staged bytes" }
    Assert-HeldIdentity $pair[0] $pair[2]
}
 $guiManifestPath = [IO.Path]::GetFullPath((Join-Path $stage 'Program Files\BootHop\boothop-gui.manifest'))
 $helperManifestPath = [IO.Path]::GetFullPath((Join-Path $stage 'Program Files\BootHop\boothop-helper.manifest'))
 $guiManifestResource = Open-HeldFileResource $guiManifestPath 'GUI manifest' $guiManifestPath; [void](Add-HeldResource $resources $guiManifestResource); $guiManifestHeld = $guiManifestResource.Held
 $helperManifestResource = Open-HeldFileResource $helperManifestPath 'helper manifest' $helperManifestPath; [void](Add-HeldResource $resources $helperManifestResource); $helperManifestHeld = $helperManifestResource.Held
Assert-ExecutionManifest $guiManifestHeld 'GUI manifest' 'asInvoker'
Assert-ExecutionManifest $helperManifestHeld 'helper manifest' 'requireAdministrator'
$policyPath = [IO.Path]::GetFullPath((Join-Path $stage 'ProgramData\BootHop\.directory-policy.json'))
$policyResource = Open-HeldFileResource $policyPath 'directory policy' $policyPath; [void](Add-HeldResource $resources $policyResource); $policyHeld = $policyResource.Held
$policy = Read-HeldText $policyHeld 'directory policy' | ConvertFrom-Json
if ($policy.schema_version -ne 1 -or $policy.path -cne 'ProgramData\BootHop' -or $policy.owner -cne 'SYSTEM-or-BUILTIN-Administrators' -or $policy.ordinary_user_access -cne 'none' -or $policy.acl_enforcement -cne 'installer-required; staging-does-not-mutate-ACL') { Fail 'ProgramData policy metadata is incorrect' }
$markerPath = [IO.Path]::GetFullPath((Join-Path $stage 'NON-PRODUCTION.txt'))
$markerResource = Open-HeldFileResource $markerPath 'non-production marker' $markerPath; [void](Add-HeldResource $resources $markerResource); $markerHeld = $markerResource.Held
if ((Read-HeldText $markerHeld 'non-production marker') -notmatch '(?i)installer.*recovery|recovery.*downgrade') { Fail 'non-production marker is incomplete' }
Write-Output 'Windows package check: passed'
} finally { Close-HeldResourceSet $resources }
