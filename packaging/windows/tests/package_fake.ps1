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
    try {
        & $action
        throw "FAIL: $message (command unexpectedly succeeded)"
    } catch {
        if ($_.Exception.Message -like "FAIL: $message*") { throw }
        if ($_.Exception.Message -notlike "*$message*") {
            throw "FAIL: expected failure reason '$message'; got '$($_.Exception.Message)'"
        }
    }
}

function New-FakePe([string] $path, [UInt16] $machine = 0x8664) {
    $bytes = [byte[]](0..255)
    $bytes[0] = 0x4d; $bytes[1] = 0x5a
    $bytes[0x3c] = 0x80; $bytes[0x3d] = 0; $bytes[0x3e] = 0; $bytes[0x3f] = 0
    $bytes[0x80] = 0x50; $bytes[0x81] = 0x45; $bytes[0x82] = 0; $bytes[0x83] = 0
    $bytes[0x84] = [byte]($machine -band 0xff); $bytes[0x85] = [byte](($machine -shr 8) -band 0xff)
    $bytes[0x98] = 0x0b; $bytes[0x99] = 0x02
    [IO.File]::WriteAllBytes($path, $bytes)
}

function New-FakeDumpbin([string] $path, [string] $body, [int] $exitCode = 0) {
    $escaped = $body.Replace("'", "''")
    @"
Write-Output '$escaped'
exit $exitCode
"@ | Set-Content -LiteralPath $path -Encoding UTF8 -NoNewline
}

$validDumpbin = "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n  Section contains the following imports:`n    KERNEL32.dll`n                       140001000 GetCurrentProcess`n                       140001001 LoadLibraryA`n                       140001002 GetProcAddress`n    ADVAPI32.dll`n                       140001003 OpenProcessToken`n"

$temp = Join-Path ([IO.Path]::GetTempPath()) ('boothop-windows-package-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $gui = Join-Path $temp 'boothop-gui.exe'
    $helper = Join-Path $temp 'boothop-helper.exe'
    New-FakePe $gui
    New-FakePe $helper
    $out = Join-Path $temp 'stage'

    & $stageScript -GuiPath $gui -HelperPath $helper -OutputPath $out
    & $packageCheck -StagePath $out
    . (Join-Path $root 'packaging\windows\held.ps1')
    $heldSource = Get-Content -LiteralPath (Join-Path $root 'packaging\windows\held.ps1') -Raw
    Assert ($heldSource -match '0x02200000u') 'directory pins must use no-follow reparse-point semantics'
    Assert ($heldSource -notmatch '(?s)function Open-HeldDirectoryPins.*?Get-Item') 'directory pin validation must be handle-authoritative'
    Assert ((Normalize-HeldPath '\\?\UNC\server\share\fixture') -ceq '\\server\share\fixture') 'UNC final paths must normalize without dropping the UNC prefix'
    Assert ((Get-Content -LiteralPath (Join-Path $root 'packaging\windows\stage.ps1') -Raw) -notmatch 'Assert-NoReparseAncestors') 'stage must not trust a path reparse check before pinning'
    Assert ((Get-Content -LiteralPath (Join-Path $root 'packaging\windows\check-capabilities.ps1') -Raw) -notmatch 'Assert-NoReparseAncestors') 'capability audit must not trust a path reparse check before pinning'
    $swapHeld = Open-HeldRead $gui 'held swap fixture' $gui
    try {
        Assert-Fails { [IO.File]::WriteAllBytes($gui, [byte[]](1,2,3)) } 'being used by another process'
        $savedIdentity = $swapHeld.Identity; $swapHeld.Identity = 'mismatched-held-identity'
        Assert-Fails { Assert-HeldIdentity $swapHeld 'held swap fixture' } 'identity changed'
        $swapHeld.Identity = $savedIdentity
    } finally { Close-Held $swapHeld }
    $directResources = New-HeldResourceSet
    try {
        $directResource = Open-HeldFileResource $gui 'direct-exception fixture' $gui
        [void](Add-HeldResource $directResources $directResource)
        try { throw 'injected direct exception' } catch { } finally { Close-HeldResourceSet $directResources }
        Assert ((Get-HeldResourceCount $directResources) -eq 0) 'direct exceptions must release every held resource'
    } finally { Close-HeldResourceSet $directResources }

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
    $manifest.program_data_policy.acl_enforcement = 'not-enforced'
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'ProgramData policy metadata is incorrect'
    $manifest.program_data_policy.acl_enforcement = 'installer-required; staging-does-not-mutate-ACL'
    $manifest.forbidden_artifacts = @('service')
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'forbidden artifact policy is incorrect'
    $manifest.forbidden_artifacts = @('service','scheduled-task','run-key','startup-shortcut','driver','bcdedit','shell-command-handler')
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8

    $stableOut = Join-Path $temp 'stable-stage'
    & $stageScript -GuiPath $gui -HelperPath $helper -OutputPath $stableOut | Out-Null
    $stableManifest = Get-Content (Join-Path $stableOut 'manifest.json') -Raw | ConvertFrom-Json
    Assert ($stableManifest.binaries.gui.sha256 -eq $manifest.binaries.gui.sha256 -and $stableManifest.binaries.helper.sha256 -eq $manifest.binaries.helper.sha256) 'repeated staging changed binary hashes'

    $before = (Get-ChildItem -LiteralPath $temp -Recurse -File | Where-Object { $_.FullName -notlike "$out\*" } | ForEach-Object FullName | Sort-Object) -join "`n"
    $stagedHelper = Join-Path $out 'Program Files\BootHop\boothop-helper.exe'
    Move-Item -LiteralPath $stagedHelper -Destination (Join-Path $temp 'helper-backup.exe')
    Assert-Fails { & $packageCheck -StagePath $out } 'missing required file: Program Files\BootHop\boothop-helper.exe'
    Move-Item -LiteralPath (Join-Path $temp 'helper-backup.exe') -Destination $stagedHelper
    $changedGui = [IO.File]::ReadAllBytes((Join-Path $out 'Program Files\BootHop\boothop-gui.exe')); $changedGui[10] = 9
    [IO.File]::WriteAllBytes((Join-Path $out 'Program Files\BootHop\boothop-gui.exe'), $changedGui)
    Assert-Fails { & $packageCheck -StagePath $out } 'GUI hash does not match staged bytes'
    Copy-Item -LiteralPath $gui -Destination (Join-Path $out 'Program Files\BootHop\boothop-gui.exe') -Force

    Assert-Fails { & $stageScript -GuiPath (Join-Path $temp 'missing.exe') -HelperPath $helper -OutputPath (Join-Path $temp 'missing-stage') } 'GUI input is missing or not a regular file'
    Copy-Item $helper (Join-Path $out 'Program Files\BootHop\unexpected.exe')
    Assert-Fails { & $packageCheck -StagePath $out } 'unexpected package file'
    Remove-Item (Join-Path $out 'Program Files\BootHop\unexpected.exe')
    $mixed = Get-Content (Join-Path $out 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $mixed.protocol_version = 1
    $mixed | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'package protocol must be v2'
    $pathAttack = $mixed
    $pathAttack.protocol_version = 2
    $pathAttack.binaries.gui.path = '..\outside.exe'
    $pathAttack | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'binary paths must remain fixed and package-local'

    Assert (($before -eq ((Get-ChildItem -LiteralPath $temp -Recurse -File | Where-Object { $_.FullName -notlike "$out\*" } | ForEach-Object FullName | Sort-Object) -join "`n")) -and -not (Test-Path (Join-Path $temp 'outside'))) 'package checks wrote outside stage'

    # Capability fixtures are copied into a disposable source tree. The fake
    # dumpbin is a disposable parser fixture; no PE is ever executed.
    $auditRoot = Join-Path $temp 'audit-source'
    New-Item -ItemType Directory -Path (Join-Path $auditRoot 'crates\platform\src\windows'), (Join-Path $auditRoot 'crates\gui\src\helper_client\windows'), (Join-Path $auditRoot 'crates\gui\ui'), (Join-Path $auditRoot 'crates\core\src'), (Join-Path $auditRoot 'crates\helper\src'), (Join-Path $auditRoot 'crates\protocol\src') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $auditRoot 'crates\gui\build.rs') -Value '// generated source boundary' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $auditRoot 'crates\gui\ui\main.slint') -Value 'export component Main {}' -Encoding UTF8
    foreach ($crate in @('core','helper','protocol')) { Set-Content -LiteralPath (Join-Path $auditRoot "crates\$crate\src\lib.rs") -Value '// fixture source' -Encoding UTF8 }
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-platform-firmware.rs') (Join-Path $auditRoot 'crates\platform\src\windows\firmware.rs')
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-platform-privilege.rs') (Join-Path $auditRoot 'crates\platform\src\windows\privilege.rs')
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-platform-reboot.rs') (Join-Path $auditRoot 'crates\platform\src\windows\reboot.rs')
    New-Item -ItemType Directory -Path (Join-Path $auditRoot 'crates\gui\src\helper_client\windows') -Force | Out-Null
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-gui-launcher.rs') (Join-Path $auditRoot 'crates\gui\src\helper_client\windows\native.rs')
    $dumpbin = Join-Path $temp 'dumpbin.ps1'
    New-FakeDumpbin $dumpbin $validDumpbin
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin } 'production dumpbin must be canonical dumpbin.exe'
    & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $root -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode
    & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode
    New-FakeDumpbin $dumpbin ($validDumpbin.Replace('GetProcAddress', 'GetProcAddressEvil'))
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'dynamic-loader import lacks audited runtime provenance'
    New-FakeDumpbin $dumpbin $validDumpbin
    New-FakeDumpbin $dumpbin ($validDumpbin.Replace('KERNEL32.dll', 'USER32.dll'))
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'dynamic-loader import lacks audited runtime provenance'
    New-FakeDumpbin $dumpbin $validDumpbin
    New-FakeDumpbin $dumpbin "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n  Section contains the following imports:`n"
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'imports table has no DLLs'
    New-FakeDumpbin $dumpbin "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n  Section contains the following imports:`n    KERNEL32.dll`n"
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'imports table has no named entries'
    New-FakeDumpbin $dumpbin "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n"
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'unrecognized dumpbin output'
    New-FakeDumpbin $dumpbin $validDumpbin
    New-FakeDumpbin $dumpbin "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n  Section contains the following imports:`n" 7
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'dumpbin failed for GUI PE'
    New-FakeDumpbin $dumpbin "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n  Section contains the following imports:`n    KERNEL32.dll`n                       ordinal 17"
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'ordinal import is unsupported'
    New-FakeDumpbin $dumpbin "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n  Section contains the following imports:`n    KERNEL32.dll`n                       140001000"
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'unrecognized import form'
    Remove-Item -LiteralPath $dumpbin
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'dumpbin is missing or not a regular file'
    New-FakeDumpbin $dumpbin "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n  Section contains the following imports:`n"
    $missingPe = Join-Path $temp 'missing-pe.exe'; Move-Item -LiteralPath $helper -Destination $missingPe
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'helper PE is missing or not a regular file'
    Move-Item -LiteralPath $missingPe -Destination $helper
    New-FakeDumpbin $dumpbin $validDumpbin
    $wrongPe = Join-Path $temp 'wrong-arch.exe'; New-FakePe $wrongPe 0x014c
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $wrongPe -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'unsupported PE machine'
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\forbidden-capabilities.rs') (Join-Path $auditRoot 'crates\gui\src\forbidden.rs')
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'source capability ''SetFirmwareEnvironmentVariable'' outside its allowlist'
    Remove-Item -LiteralPath (Join-Path $auditRoot 'crates\gui\src\forbidden.rs')
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\allowed-platform-firmware.rs') (Join-Path $auditRoot 'crates\platform\src\windows\firmware.rs.bak')
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $auditRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'source capability ''SetFirmwareEnvironmentVariable'' outside its allowlist'
    Remove-Item -LiteralPath (Join-Path $auditRoot 'crates\platform\src\windows\firmware.rs.bak')
    $junctionTarget = Join-Path $temp 'junction-target'; New-Item -ItemType Directory -Path $junctionTarget -Force | Out-Null
    Copy-Item -LiteralPath $gui -Destination (Join-Path $junctionTarget 'boothop-gui.exe')
    $junction = Join-Path $temp 'junction-root'
    try { New-Item -ItemType Junction -Path $junction -Target $junctionTarget -ErrorAction Stop | Out-Null }
    catch { throw "FAIL: unable to create required directory junction fixture: $($_.Exception.Message)" }
    Assert-Fails { Open-HeldDirectoryPins $junction 'junction fixture' $junction } 'contains a reparse point'
    Assert-Fails { & $stageScript -GuiPath (Join-Path $junction 'boothop-gui.exe') -HelperPath $helper -OutputPath (Join-Path $temp 'reparse-stage') } 'GUI contains a reparse point'
    Remove-Item -LiteralPath $junction -Force
    $emptyRoot = Join-Path $temp 'empty-source'; New-Item -ItemType Directory -Path $emptyRoot -Force | Out-Null
    Assert-Fails { & (Join-Path $root 'packaging\windows\check-capabilities.ps1') -RootPath $emptyRoot -GuiPath $gui -HelperPath $helper -DumpbinPath $dumpbin -TestOnlyFixtureMode } 'source root crates\core\src is missing or not a directory'
    New-FakeDumpbin $dumpbin "Dump of file fixture`n  File Type: EXECUTABLE IMAGE`n  Section contains the following imports:`n"
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    $guiManifest = Join-Path $out 'Program Files\BootHop\boothop-gui.manifest'
    $goodXml = Get-Content -LiteralPath $guiManifest -Raw
    Set-Content -LiteralPath $guiManifest -Value ($goodXml -replace '</requestedPrivileges>', '<!-- requestedExecutionLevel level="requireAdministrator" --></requestedPrivileges>') -Encoding UTF8 -NoNewline
    Assert-Fails { & $packageCheck -StagePath $out } 'GUI manifest contains a requestedExecutionLevel spoof in a comment'
    Set-Content -LiteralPath $guiManifest -Value '<assembly>' -Encoding UTF8 -NoNewline
    Assert-Fails { & $packageCheck -StagePath $out } 'GUI manifest is not well-formed XML'
    $duplicateXml = $goodXml -replace '</requestedPrivileges>', '<requestedExecutionLevel level="asInvoker" uiAccess="false" /></requestedPrivileges>'
    Set-Content -LiteralPath $guiManifest -Value $duplicateXml -Encoding UTF8 -NoNewline
    Assert-Fails { & $packageCheck -StagePath $out } 'GUI manifest must contain exactly one requestedExecutionLevel'
    $wrongRootXml = $goodXml.Replace('<assembly ','<wrongRoot ').Replace('</assembly>','</wrongRoot>')
    Set-Content -LiteralPath $guiManifest -Value $wrongRootXml -Encoding UTF8 -NoNewline
    Assert-Fails { & $packageCheck -StagePath $out } 'GUI manifest root must be assembly in the asm.v1 namespace'
    $wrongNamespaceXml = $goodXml.Replace('urn:schemas-microsoft-com:asm.v1','urn:schemas-example:asm.v1')
    Set-Content -LiteralPath $guiManifest -Value $wrongNamespaceXml -Encoding UTF8 -NoNewline
    Assert-Fails { & $packageCheck -StagePath $out } 'GUI manifest root must be assembly in the asm.v1 namespace'
    $relocatedXml = $goodXml.Replace('<requestedPrivileges>','<requestedPrivileges><spoof />')
    Set-Content -LiteralPath $guiManifest -Value $relocatedXml -Encoding UTF8 -NoNewline
    Assert-Fails { & $packageCheck -StagePath $out } 'GUI manifest document hierarchy is not exact'
    Set-Content -LiteralPath $guiManifest -Value $goodXml -Encoding UTF8 -NoNewline
    $manifest = Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json
    $manifest.architecture = 'x86_64-pc-windows-gnu'
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'unsupported or missing architecture'
    $manifest.architecture = 'x86_64-pc-windows-msvc'
    $manifest.binaries.gui.sha256 = $manifest.binaries.gui.sha256.ToUpperInvariant()
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'GUI hash is absent or malformed'
    $manifest.binaries.gui.sha256 = (Get-FileHash -LiteralPath (Join-Path $out 'Program Files\BootHop\boothop-gui.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $wrongStaged = Join-Path $temp 'wrong-staged.exe'; New-FakePe $wrongStaged 0x014c
    Copy-Item -LiteralPath $wrongStaged -Destination (Join-Path $out 'Program Files\BootHop\boothop-gui.exe') -Force
    $manifest.binaries.gui.sha256 = (Get-FileHash -LiteralPath (Join-Path $out 'Program Files\BootHop\boothop-gui.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.binaries.gui.size = (Get-Item -LiteralPath (Join-Path $out 'Program Files\BootHop\boothop-gui.exe')).Length
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'unsupported PE machine'
    Copy-Item -LiteralPath $gui -Destination (Join-Path $out 'Program Files\BootHop\boothop-gui.exe') -Force
    $manifest.layout.program_files = 'program files\BootHop'
    $manifest.binaries.gui.sha256 = (Get-FileHash -LiteralPath (Join-Path $out 'Program Files\BootHop\boothop-gui.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.binaries.gui.size = (Get-Item -LiteralPath (Join-Path $out 'Program Files\BootHop\boothop-gui.exe')).Length
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -NoNewline -Encoding UTF8
    Assert-Fails { & $packageCheck -StagePath $out } 'fixed layout metadata is incorrect'

    # Behavioral regression: the production launcher must validate dumpbin's
    # image identity while the process is still running.  Querying a retained
    # process handle after WaitForExit returns ERROR_GEN_FAILURE (31) on
    # Windows, even with PROCESS_QUERY_LIMITED_INFORMATION.  Use the release
    # PEs built by the CI job and stage them through the normal non-installing
    # path; this is deliberately not the test-only .ps1 fixture seam.
    $releaseGui = Join-Path $root 'target\release\boothop-gui.exe'
    $releaseHelper = Join-Path $root 'target\release\boothop-helper.exe'
    Assert (Test-Path -LiteralPath $releaseGui -PathType Leaf) 'release GUI PE is required for production identity regression'
    Assert (Test-Path -LiteralPath $releaseHelper -PathType Leaf) 'release helper PE is required for production identity regression'
    $releaseStage = Join-Path $temp 'release-stage'
    & $stageScript -GuiPath $releaseGui -HelperPath $releaseHelper -OutputPath $releaseStage | Out-Null
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    Assert (Test-Path -LiteralPath $vswhere -PathType Leaf) 'vswhere.exe is required for production identity regression'
    $realDumpbin = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find '**\dumpbin.exe' | Select-Object -First 1
    Assert (-not [string]::IsNullOrWhiteSpace($realDumpbin) -and (Test-Path -LiteralPath $realDumpbin -PathType Leaf)) 'dumpbin.exe is required for production identity regression'
    & (Join-Path $root 'packaging\windows\check-capabilities.ps1') `
        -RootPath $root `
        -GuiPath (Join-Path $releaseStage 'Program Files\BootHop\boothop-gui.exe') `
        -HelperPath (Join-Path $releaseStage 'Program Files\BootHop\boothop-helper.exe') `
        -DumpbinPath $realDumpbin

    # Bounded cleanup regression: inject a process-image query failure after
    # launching the real dumpbin (never BootHop).  The child produces enough
    # redirected output to fill a pipe if the launcher waits for cleanup
    # before starting both async drains.  Run the audit in a child with a
    # hard timeout so the pre-fix behavior is a deterministic RED result,
    # rather than allowing the fixture test itself to hang.
    $probeScript = Join-Path $root 'packaging\windows\check-capabilities.ps1'
    $probe = [Diagnostics.Process]::new()
    $probe.StartInfo = [Diagnostics.ProcessStartInfo]::new()
    $probe.StartInfo.FileName = (Get-Process -Id $PID).Path
    $probe.StartInfo.UseShellExecute = $false
    $probe.StartInfo.RedirectStandardOutput = $true
    $probe.StartInfo.RedirectStandardError = $true
    foreach ($arg in @('-NoProfile', '-File', $probeScript,
        '-RootPath', $root,
        '-GuiPath', (Join-Path $releaseStage 'Program Files\BootHop\boothop-gui.exe'),
        '-HelperPath', (Join-Path $releaseStage 'Program Files\BootHop\boothop-helper.exe'),
        '-DumpbinPath', $realDumpbin,
        '-TestOnlyFixtureMode', '-TestOnlyInjectProcessImageFailure')) {
        [void]$probe.StartInfo.ArgumentList.Add($arg)
    }
    $probeWatch = [Diagnostics.Stopwatch]::StartNew()
    Assert $probe.Start() 'identity-failure cleanup probe failed to start'
    $probeOut = $probe.StandardOutput.ReadToEndAsync()
    $probeErr = $probe.StandardError.ReadToEndAsync()
    if (-not $probe.WaitForExit(5000)) {
        try { $probe.Kill($true); $probe.WaitForExit() } catch { }
        throw 'FAIL: injected identity failure cleanup exceeded 5 seconds'
    }
    $probeWatch.Stop()
    Assert ($probe.ExitCode -ne 0) 'injected identity failure unexpectedly succeeded'
    $probeText = [string]::Concat($probeOut.Result, $probeErr.Result)
    Assert ($probeText -match 'injected process image failure') 'identity-failure cleanup probe did not report the injected failure'
    Assert ($probeWatch.Elapsed.TotalSeconds -lt 5) 'identity-failure cleanup probe exceeded its bound'
    $probe.Dispose()
    Write-Output 'Windows package fake tests: passed'
}
finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
