[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [Alias('Stage','Path','RootPath','OutputPath')]
    [string] $StagePath
)

$ErrorActionPreference = 'Stop'
function Fail([string] $message) { throw "Windows package check failed: $message" }
if (-not [IO.Path]::IsPathRooted($StagePath)) { Fail 'stage path must be absolute' }
$stage = (Resolve-Path -LiteralPath $StagePath -ErrorAction Stop).Path
if ((Get-Item -LiteralPath $stage).Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail 'stage root must not be a reparse point' }

$required = @(
    'manifest.json', 'NON-PRODUCTION.txt',
    'Program Files\BootHop\boothop-gui.exe',
    'Program Files\BootHop\boothop-helper.exe',
    'Program Files\BootHop\boothop-gui.manifest',
    'Program Files\BootHop\boothop-helper.manifest',
    'ProgramData\BootHop\.directory-policy.json'
)
$requiredDirs = @('Program Files', 'Program Files\BootHop', 'ProgramData', 'ProgramData\BootHop')
$actualDirs = @(Get-ChildItem -LiteralPath $stage -Recurse -Directory -Force | ForEach-Object {
    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "reparse-point directory is forbidden: $($_.FullName)" }
    [IO.Path]::GetRelativePath($stage, $_.FullName).Replace('/','\')
}) | Sort-Object
foreach ($name in $requiredDirs) { if ($actualDirs -notcontains $name) { Fail "missing required directory: $name" } }
foreach ($name in $actualDirs) { if ($requiredDirs -notcontains $name) { Fail "unexpected package directory: $name" } }
$actual = @(Get-ChildItem -LiteralPath $stage -Recurse -File -Force | ForEach-Object {
    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "reparse-point file is forbidden: $($_.FullName)" }
    [IO.Path]::GetRelativePath($stage, $_.FullName).Replace('/','\')
}) | Sort-Object
foreach ($name in $required) { if ($actual -notcontains $name) { Fail "missing required file: $name" } }
foreach ($name in $actual) { if ($required -notcontains $name) { Fail "unexpected package file: $name" } }
foreach ($dir in @(Get-ChildItem -LiteralPath $stage -Recurse -Directory -Force)) {
    if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "reparse-point directory is forbidden: $($dir.FullName)" }
}

$manifest = Get-Content -LiteralPath (Join-Path $stage 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.product -ne 'BootHop') { Fail 'invalid manifest identity' }
if ($manifest.production_status -ne 'NON-PRODUCTION') { Fail 'missing NON-PRODUCTION status' }
if ($manifest.architecture -ne 'x86_64-pc-windows-msvc') { Fail 'unsupported or missing architecture' }
if ($manifest.protocol_version -ne 2) { Fail 'package protocol must be v2' }
if ($manifest.publisher -ne 'UNSIGNED-DEVELOPMENT-PLACEHOLDER') { Fail 'publisher must remain an explicit placeholder' }
if ($manifest.signing.status -ne 'UNSIGNED-PLACEHOLDER') { Fail 'signing status must remain an explicit placeholder' }
if ($manifest.layout.gui -ne 'Program Files\BootHop\boothop-gui.exe' -or $manifest.layout.helper -ne 'Program Files\BootHop\boothop-helper.exe' -or $manifest.layout.record -ne 'ProgramData\BootHop\targets.json') { Fail 'fixed layout metadata is incorrect' }
if ($manifest.binaries.gui.protocol_version -ne 2 -or $manifest.binaries.helper.protocol_version -ne 2) { Fail 'mixed binary protocol metadata' }
if ($manifest.binaries.gui.execution_level -ne 'asInvoker' -or $manifest.binaries.helper.execution_level -ne 'requireAdministrator') { Fail 'binary execution level metadata is incorrect' }
if ($manifest.binaries.gui.path -ne 'Program Files\BootHop\boothop-gui.exe' -or $manifest.binaries.helper.path -ne 'Program Files\BootHop\boothop-helper.exe') { Fail 'binary paths must remain fixed and package-local' }
if ($manifest.program_data_policy.owner -ne 'SYSTEM-or-BUILTIN-Administrators' -or $manifest.program_data_policy.ordinary_user_access -ne 'none') { Fail 'ProgramData policy metadata is incorrect' }
$gui = Join-Path $stage $manifest.binaries.gui.path
$helper = Join-Path $stage $manifest.binaries.helper.path
foreach ($pair in @(@($gui,$manifest.binaries.gui.sha256,'GUI'), @($helper,$manifest.binaries.helper.sha256,'helper'))) {
    if ($pair[1] -notmatch '^[0-9a-f]{64}$') { Fail "$($pair[2]) hash is absent or malformed" }
    $hash = (Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $pair[1]) { Fail "$($pair[2]) hash does not match staged bytes" }
}
if ((Get-Content (Join-Path $stage 'Program Files\BootHop\boothop-gui.manifest') -Raw) -notmatch 'requestedExecutionLevel level="asInvoker"') { Fail 'GUI manifest is not asInvoker' }
if ((Get-Content (Join-Path $stage 'Program Files\BootHop\boothop-helper.manifest') -Raw) -notmatch 'requestedExecutionLevel level="requireAdministrator"') { Fail 'helper manifest is not requireAdministrator' }
if ((Get-Content (Join-Path $stage 'NON-PRODUCTION.txt') -Raw) -notmatch '(?i)installer.*recovery|recovery.*downgrade') { Fail 'non-production marker is incomplete' }
Write-Output 'Windows package check: passed'
