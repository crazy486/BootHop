[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$scriptPath = Join-Path $root 'packaging\windows\update-acceptance.ps1'
function Assert([bool]$condition, [string]$message) { if (-not $condition) { throw "FAIL: $message" } }
function Assert-Fails([scriptblock]$action, [string]$message) {
    try { & $action; throw "FAIL: unexpectedly succeeded: $message" }
    catch { if ($_.Exception.Message.StartsWith('FAIL:') -or $_.Exception.Message -notlike "*$message*") { throw } }
}
# Load only function definitions. Never invoke the fixed-path elevated entry point.
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
Assert ($errors.Count -eq 0) 'updater must parse'
foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
. (Join-Path $root 'packaging\windows\held.ps1')

function New-AclFixture([string]$owner = 'S-1-5-32-544') {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($owner))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow'))
    }
    return $acl
}
$acl = New-AclFixture
Assert-AcceptanceAcl $acl 'fixture' -NoOrdinaryAccess
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'Allow'))
Assert-AcceptanceAcl $acl 'fixture'
Assert-Fails { Assert-AcceptanceAcl $acl 'fixture' -NoOrdinaryAccess } 'ordinary access'
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Write', 'Allow'))
Assert-Fails { Assert-AcceptanceAcl $acl 'fixture' } 'ordinary write'
Assert-Fails { Assert-AcceptanceAcl (New-AclFixture 'S-1-5-32-545') 'fixture' } 'owner'
$creatorAcl = New-AclFixture
$creatorAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-3-0'), 'FullControl', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow'))
Assert-AcceptanceAcl $creatorAcl 'trusted owner fixture'
$acl = New-AclFixture
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Write', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow'))
Assert-Fails { Assert-AcceptanceAcl $acl 'fixture' } 'ordinary write'
$acl = New-AclFixture
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'DeleteSubdirectoriesAndFiles', 'Allow'))
Assert-Fails { Assert-AcceptanceAcl $acl 'fixture' -ParentBoundary } 'ordinary write'

# The existing Program Files child inherits TrustedInstaller FullControl, plus
# an inherit-only GenericAll ACE. Only that inherited Windows service ACE may
# be trusted at the install directory; ordinary Users Write must still fail.
$installerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$installAcl = [Security.AccessControl.DirectorySecurity]::new()
$installAcl.SetSecurityDescriptorSddlForm("O:BAG:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;$installerSid)(A;CIIOID;GA;;;$installerSid)(A;ID;0x1200a9;;;BU)")
Assert-Fails { Assert-AcceptanceAcl $installAcl 'install fixture' } 'ordinary write'
Assert-AcceptanceAcl $installAcl 'install fixture' -TrustedInstallerInherited
$installAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Write', 'Allow'))
Assert-Fails { Assert-AcceptanceAcl $installAcl 'install fixture' -TrustedInstallerInherited } 'ordinary write'
$explicitInstallerAcl = New-AclFixture
$explicitInstallerAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($installerSid), 'FullControl', 'Allow'))
Assert-Fails { Assert-AcceptanceAcl $explicitInstallerAcl 'explicit installer fixture' -TrustedInstallerInherited } 'ordinary write'

$identity = Get-AcceptanceIdentity
$manifest = [pscustomobject]@{architecture='x86_64-pc-windows-msvc';protocol_version=2;production_status='NON-PRODUCTION';binaries=[pscustomobject]@{}}
$provenance = [pscustomobject]@{schema_version=1;source_commit=$identity.Commit;workflow_run_id=$identity.Run;architecture=$manifest.architecture;protocol_version=2;production_status='NON-PRODUCTION'}
foreach ($name in @('gui','helper')) {
    $expected = $identity.Binaries[$name]
    $binary = [pscustomobject]@{sha256=$expected.Hash;size=$expected.Size;execution_level=$expected.Level;protocol_version=2}
    $manifest.binaries | Add-Member -NotePropertyName $name -NotePropertyValue $binary
    $provenance | Add-Member -NotePropertyName $name -NotePropertyValue ([pscustomobject]@{sha256=$expected.Hash;size=$expected.Size;execution_level=$expected.Level;relative_path="stage/Program Files/BootHop/boothop-$name.exe";authenticode_status='NotSigned'})
}
Assert-AcceptanceProvenance $provenance $manifest
$provenance.source_commit = '0000000000000000000000000000000000000000'
Assert-Fails { Assert-AcceptanceProvenance $provenance $manifest } 'commit/run'
$provenance.source_commit = $identity.Commit
$provenance.workflow_run_id = '0'
Assert-Fails { Assert-AcceptanceProvenance $provenance $manifest } 'commit/run'
$provenance.workflow_run_id = $identity.Run
$provenance.gui.sha256 = '0' * 64; $manifest.binaries.gui.sha256 = '0' * 64
Assert-Fails { Assert-AcceptanceProvenance $provenance $manifest } 'pinned GUI identity'
$provenance.gui.sha256 = $identity.Binaries.gui.Hash; $manifest.binaries.gui.sha256 = $identity.Binaries.gui.Hash
$provenance.helper.size++
Assert-Fails { Assert-AcceptanceProvenance $provenance $manifest } 'pinned helper identity'
$provenance.helper.size--
$provenance.helper.execution_level = 'asInvoker'
Assert-Fails { Assert-AcceptanceProvenance $provenance $manifest } 'pinned helper identity'
$provenance.helper.execution_level = 'requireAdministrator'
$provenance.helper.relative_path = '../boothop-helper.exe'
Assert-Fails { Assert-AcceptanceProvenance $provenance $manifest } 'pinned helper identity'

Assert ((Get-AcceptanceProcessDisposition 'C:\Other\boothop-gui.exe' @('C:\Program Files\BootHop\boothop-gui.exe')) -ceq 'Ignore') 'unrelated basename must survive'
Assert ((Get-AcceptanceProcessDisposition 'c:\program files\boothop\boothop-gui.exe' @('C:\Program Files\BootHop\boothop-gui.exe')) -ceq 'Stop') 'only fixed full path is selected'
Assert-Fails { Get-AcceptanceProcessDisposition '' @('C:\Program Files\BootHop\boothop-gui.exe') } 'identity uncertain'
Assert-Fails { Get-AcceptanceProcessDisposition '\Device\HarddiskVolume3\boothop-gui.exe' @('C:\Program Files\BootHop\boothop-gui.exe') } 'identity uncertain'

$temp = Join-Path ([IO.Path]::GetTempPath()) ('boothop-update-fixture-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $source = Join-Path $temp 'source.bin'; [IO.File]::WriteAllBytes($source, [byte[]](1,2,3,4))
    $held = Open-HeldFileResource $source 'source fixture' $source
    try {
        $hash = Get-HeldHash $held.Held
        $candidate = Join-Path $temp 'candidate.tmp'
        Write-AcceptanceCopy $held.Held $candidate $hash 4
        Assert ((Get-FileHash $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $hash) 'copy consumes the held bytes'
        Assert-Fails { Write-AcceptanceCopy $held.Held $candidate $hash 4 } 'already exists'
        Assert-Fails { [IO.File]::WriteAllBytes($source, [byte[]](5)) } 'being used by another process'
        Assert-Fails { Write-AcceptanceCopy $held.Held (Join-Path $temp 'bad.tmp') ('0' * 64) 4 } 'copy hash/size'
    } finally { Close-Held $held }
    $target = Join-Path $temp 'target.exe'; [IO.File]::WriteAllBytes($target,[byte[]](9))
    $untouched = Join-Path $temp 'protected-record.json'; [IO.File]::WriteAllText($untouched,'preserve')
    $entries = [pscustomobject]@{Name='fixture';Path=$target;Temporary=$candidate;Existing=(Open-HeldFileResource $target 'existing fixture' $target);Expected=@{Hash=$hash;Size=4}}
    $resources = New-HeldResourceSet; $replaced = [Collections.Generic.List[string]]::new()
    try {
        Invoke-AcceptanceReplace $entries $resources $replaced {
            param($path)
            Assert ($path.StartsWith($temp + [IO.Path]::DirectorySeparatorChar)) 'fixture cannot touch live layout'
        }
        Assert ($replaced.Count -eq 1 -and $replaced[0] -ceq 'fixture') 'replacement helper records exactly the completed replacement'
    } finally { Close-Held $entries.Existing; Close-HeldResourceSet $resources }
    Assert ((Get-FileHash $target -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $hash) 'real per-file replacement is verified'
    Assert ([IO.File]::ReadAllText($untouched) -ceq 'preserve') 'sibling protected record remains unchanged'
    $link = Join-Path $temp 'junction'
    New-Item -ItemType Junction -Path $link -Target $temp | Out-Null
    Assert-Fails { Open-HeldDirectoryPins $link 'fixture junction' $link } 'reparse point'
    [IO.Directory]::Delete($link)
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
Write-Output 'Windows acceptance updater fixtures: passed (no live layout, process stop, or PE execution)'
