[CmdletBinding()]
param(
    [Alias('Root','SourceRoot')]
    [string] $RootPath = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [Parameter(Mandatory=$true)] [Alias('Gui','GuiPe')] [string] $GuiPath,
    [Parameter(Mandatory=$true)] [Alias('Helper','HelperPe')] [string] $HelperPath,
    [Parameter(Mandatory=$true)] [Alias('Dumpbin','DumpbinExe')] [string] $DumpbinPath
)

$ErrorActionPreference = 'Stop'
function Fail([string] $message) { throw "Windows capability audit failed: $message" }
if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) { Fail 'source root is missing' }
if (-not (Test-Path -LiteralPath $DumpbinPath -PathType Leaf)) { Fail 'dumpbin.exe is missing' }
foreach ($pe in @($GuiPath,$HelperPath)) { if (-not (Test-Path -LiteralPath $pe -PathType Leaf)) { Fail "produced PE is missing: $pe" } }

$rules = @(
    @{ Pattern='SetFirmwareEnvironmentVariable'; Allowed='platform\src\windows\firmware.rs' },
    @{ Pattern='GetFirmwareEnvironmentVariable'; Allowed='platform\src\windows\firmware.rs' },
    @{ Pattern='GetFirmwareType'; Allowed='platform\src\windows\firmware.rs' },
    @{ Pattern='AdjustTokenPrivileges'; Allowed='platform\src\windows\privilege.rs' },
    @{ Pattern='OpenProcessToken'; Allowed=@('platform\src\windows\privilege.rs','gui\src\helper_client\windows','helper\src\windows') },
    @{ Pattern='InitiateSystemShutdown'; Allowed='platform\src\windows\reboot.rs' },
    @{ Pattern='ExitWindows'; Allowed='platform\src\windows\reboot.rs' },
    @{ Pattern='ShellExecute'; Allowed='gui\src\helper_client\windows' },
    @{ Pattern='CreateProcess'; Allowed='gui\src\helper_client\windows' },
    @{ Pattern='LoadLibrary'; Allowed=$null },
    @{ Pattern='GetProcAddress'; Allowed=$null },
    @{ Pattern='bcdedit'; Allowed=$null }
)
$sourceFiles = @(Get-ChildItem -LiteralPath (Join-Path $RootPath 'crates') -Directory -Force | ForEach-Object {
    $src = Join-Path $_.FullName 'src'
    if (Test-Path -LiteralPath $src -PathType Container) {
        Get-ChildItem -LiteralPath $src -Recurse -File -Include '*.rs','*.c','*.h' -Force
    }
})
foreach ($file in $sourceFiles) {
    $relative = [IO.Path]::GetRelativePath($RootPath, $file.FullName).Replace('/','\')
    $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
    foreach ($rule in $rules) {
        if ($text -match [regex]::Escape($rule.Pattern)) {
            $allowed = $false
            if ($null -ne $rule.Allowed) {
                foreach ($allow in @($rule.Allowed)) {
                    if ($relative -like "*$allow*") { $allowed = $true; break }
                }
            }
            if (-not $allowed) { Fail "source capability '$($rule.Pattern)' is outside its allowlist: $relative" }
        }
    }
}

function Get-Imports([string] $pe) {
    $lines = @(& $DumpbinPath /imports $pe 2>&1)
    $commandOk = $?
    if (-not $commandOk -or ($DumpbinPath -notmatch '\.ps1$' -and $LASTEXITCODE -ne 0)) { Fail "dumpbin failed for $pe" }
    return ($lines -join "`n")
}
$guiImports = Get-Imports $GuiPath
$helperImports = Get-Imports $HelperPath
$guiForbidden = 'SetFirmwareEnvironmentVariable|GetFirmwareEnvironmentVariable|AdjustTokenPrivileges|InitiateSystemShutdown|ExitWindows|CreateProcess|LoadLibrary|GetProcAddress|bcdedit'
$helperForbidden = 'LoadLibrary|GetProcAddress|bcdedit|CreateProcess|ShellExecute'
if ($guiImports -match $guiForbidden) { Fail 'GUI PE imports a forbidden capability' }
if ($helperImports -match $helperForbidden) { Fail 'helper PE imports a forbidden process/dynamic-loader capability' }
Write-Output 'Windows source and PE capability audit: passed'
