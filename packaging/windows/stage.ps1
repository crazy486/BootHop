[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [Alias('Gui','ReleaseGui','GuiBinary','GuiInput','ReleaseGuiPath')]
    [string] $GuiPath,
    [Parameter(Mandatory=$true, Position=1)]
    [Alias('Helper','ReleaseHelper','HelperBinary','HelperInput','ReleaseHelperPath')]
    [string] $HelperPath,
    [Parameter(Mandatory=$true, Position=2)]
    [Alias('Output','Stage','StagePath','OutputDir','Destination')]
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$scriptRoot = (Resolve-Path $PSScriptRoot).Path

function Fail([string] $message) { throw "Windows package staging failed: $message" }
function Require-RegularFile([string] $path, [string] $label) {
    if (-not [IO.Path]::IsPathRooted($path)) { Fail "$label input must be an absolute path" }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or -not ($item.PSIsContainer -eq $false)) { Fail "$label input is missing or not a regular file" }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$label input must not be a reparse point" }
    return $item
}

$gui = Require-RegularFile $GuiPath 'GUI'
$helper = Require-RegularFile $HelperPath 'helper'
if (-not [IO.Path]::IsPathRooted($OutputPath)) { Fail 'output must be an absolute path' }
$output = [IO.Path]::GetFullPath($OutputPath)
if ($output -eq [IO.Path]::GetPathRoot($output)) { Fail 'refusing a filesystem root as output' }
$probe = $output
while ($null -ne $probe -and $probe -ne [IO.Path]::GetPathRoot($probe)) {
    if (Test-Path -LiteralPath $probe) {
        $probeItem = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if ($probeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "output path contains a reparse point: $probe" }
    }
    $nextProbe = Split-Path -Path $probe -Parent
    if ($nextProbe -eq $probe) { break }
    $probe = $nextProbe
}
if (Test-Path -LiteralPath $output) {
    $existing = Get-ChildItem -LiteralPath $output -Force -ErrorAction Stop
    if ($existing.Count -gt 0) { Fail 'output directory must be absent or empty' }
} else {
    New-Item -ItemType Directory -Path $output -Force | Out-Null
}

$programFiles = Join-Path $output 'Program Files\BootHop'
$programData = Join-Path $output 'ProgramData\BootHop'
New-Item -ItemType Directory -Path $programFiles, $programData -Force | Out-Null
Copy-Item -LiteralPath $gui.FullName -Destination (Join-Path $programFiles 'boothop-gui.exe')
Copy-Item -LiteralPath $helper.FullName -Destination (Join-Path $programFiles 'boothop-helper.exe')
Copy-Item -LiteralPath (Join-Path $scriptRoot 'boothop-gui.manifest') -Destination (Join-Path $programFiles 'boothop-gui.manifest')
Copy-Item -LiteralPath (Join-Path $scriptRoot 'boothop-helper.manifest') -Destination (Join-Path $programFiles 'boothop-helper.manifest')

$policy = [ordered]@{
    schema_version = 1
    path = 'ProgramData\BootHop'
    owner = 'SYSTEM-or-BUILTIN-Administrators'
    ordinary_user_access = 'none'
    note = 'Intent metadata only; staging never creates, changes, or validates a live ACL.'
}
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
