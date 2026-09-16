[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$stageScript = Join-Path $root 'packaging\windows\stage.ps1'
$packageCheck = Join-Path $root 'packaging\windows\check-package.ps1'

function Assert([bool]$condition, [string]$message) {
    if (-not $condition) { throw "FAIL: $message" }
}

function Assert-Fails([scriptblock]$action, [string]$message) {
    try { & $action; throw "FAIL: $message (command unexpectedly succeeded)" }
    catch { if ($_.Exception.Message -like "FAIL: $message*") { throw } }
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('boothop-windows-package-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $gui = Join-Path $temp 'boothop-gui.exe'
    $helper = Join-Path $temp 'boothop-helper.exe'
    [IO.File]::WriteAllBytes($gui, [byte[]](1, 2, 3, 4))
    [IO.File]::WriteAllBytes($helper, [byte[]](5, 6, 7, 8))
    $out = Join-Path $temp 'stage'

    & $stageScript -GuiPath $gui -HelperPath $helper -OutputPath $out
    & $packageCheck -StagePath $out

    $manifest = Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json
    Assert ($manifest.protocol_version -eq 2) 'protocol version must be 2'
    Assert ($manifest.production_status -eq 'NON-PRODUCTION') 'stage must be marked non-production'
    Assert ($manifest.architecture -eq 'x86_64-pc-windows-msvc') 'architecture must be explicit'
    Assert ($manifest.binaries.gui.protocol_version -eq 2 -and $manifest.binaries.helper.protocol_version -eq 2) 'binary metadata must match protocol v2'
    Assert (Test-Path (Join-Path $out 'Program Files\BootHop\boothop-gui.exe')) 'GUI is not in fixed Program Files layout'
    Assert (Test-Path (Join-Path $out 'Program Files\BootHop\boothop-helper.exe')) 'helper is not in fixed Program Files layout'
    Assert (Test-Path (Join-Path $out 'ProgramData\BootHop\.directory-policy.json')) 'ProgramData policy metadata is missing'
    Assert (-not (Test-Path (Join-Path $out 'ProgramData\BootHop\targets.json')) ) 'staging must not create a target record'
    Assert ((Get-Content (Join-Path $out 'NON-PRODUCTION.txt') -Raw) -match 'installer|recovery|downgrade') 'non-production marker must explain release blockers'
    Assert ((Get-Content (Join-Path $out 'Program Files\BootHop\boothop-gui.manifest') -Raw) -match 'asInvoker') 'GUI manifest must be asInvoker'
    Assert ((Get-Content (Join-Path $out 'Program Files\BootHop\boothop-helper.manifest') -Raw) -match 'requireAdministrator') 'helper manifest must requireAdministrator'

    $stableOut = Join-Path $temp 'stable-stage'
    & $stageScript -GuiPath $gui -HelperPath $helper -OutputPath $stableOut | Out-Null
    $stableManifest = Get-Content (Join-Path $stableOut 'manifest.json') -Raw | ConvertFrom-Json
    Assert ($stableManifest.binaries.gui.sha256 -eq $manifest.binaries.gui.sha256 -and $stableManifest.binaries.helper.sha256 -eq $manifest.binaries.helper.sha256) 'repeated staging changed binary hashes'

    $before = (Get-ChildItem -LiteralPath $temp -Recurse -File | Where-Object { $_.FullName -notlike "$out\*" } | ForEach-Object FullName | Sort-Object) -join "`n"
    $stagedHelper = Join-Path $out 'Program Files\BootHop\boothop-helper.exe'
    Move-Item -LiteralPath $stagedHelper -Destination (Join-Path $temp 'helper-backup.exe')
    Assert-Fails { & $packageCheck -StagePath $out } 'missing required file: Program Files\BootHop\boothop-helper.exe'
    Move-Item -LiteralPath (Join-Path $temp 'helper-backup.exe') -Destination $stagedHelper
    [IO.File]::WriteAllBytes((Join-Path $out 'Program Files\BootHop\boothop-gui.exe'), [byte[]](9, 8, 7, 6))
    Assert-Fails { & $packageCheck -StagePath $out } 'changed staged binary hash'

    Assert-Fails { & $stageScript -GuiPath (Join-Path $temp 'missing.exe') -HelperPath $helper -OutputPath (Join-Path $temp 'missing-stage') } 'missing GUI input'
    Copy-Item $helper (Join-Path $out 'Program Files\BootHop\unexpected.exe')
    Assert-Fails { & $packageCheck -StagePath $out } 'extra staged artifact'
    Remove-Item (Join-Path $out 'Program Files\BootHop\unexpected.exe')
    $mixed = Get-Content (Join-Path $out 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $mixed.protocol_version = 1
    $mixed | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'mixed protocol metadata'
    $pathAttack = $mixed
    $pathAttack.protocol_version = 2
    $pathAttack.binaries.gui.path = '..\outside.exe'
    $pathAttack | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'binary paths must remain fixed and package-local'

    Assert (($before -eq ((Get-ChildItem -LiteralPath $temp -Recurse -File | Where-Object { $_.FullName -notlike "$out\*" } | ForEach-Object FullName | Sort-Object) -join "`n")) -and -not (Test-Path (Join-Path $temp 'outside'))) 'package checks wrote outside stage'

    # Capability fixtures are copied into a disposable source tree. The fake
    # dumpbin emits no imports; no PE is ever executed.
    $auditRoot = Join-Path $temp 'audit-source'
    New-Item -ItemType Directory -Path (Join-Path $auditRoot 'crates\platform\src\windows'), (Join-Path $auditRoot 'crates\gui\src') -Force | Out-Null
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-platform-firmware.rs') (Join-Path $auditRoot 'crates\platform\src\windows\firmware.rs')
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-platform-privilege.rs') (Join-Path $auditRoot 'crates\platform\src\windows\privilege.rs')
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-platform-reboot.rs') (Join-Path $auditRoot 'crates\platform\src\windows\reboot.rs')
    New-Item -ItemType Directory -Path (Join-Path $auditRoot 'crates\gui\src\helper_client\windows') -Force | Out-Null
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-gui-launcher.rs') (Join-Path $auditRoot 'crates\gui\src\helper_client\windows\native.rs')
    $dumpbin = Join-Path $temp 'dumpbin.ps1'
    "Write-Output 'Imports for `$($args[1])'" | Set-Content -LiteralPath $dumpbin -Encoding UTF8
    & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $root -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin
    & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\forbidden-capabilities.rs') (Join-Path $auditRoot 'crates\gui\src\forbidden.rs')
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin } 'source capability ''SetFirmwareEnvironmentVariable'' outside its allowlist'
    Write-Output 'Windows package fake tests: passed'
}
finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
