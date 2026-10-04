# Acceptance preparation only. No installer, recovery mechanism, or PE execution.
[CmdletBinding(DefaultParameterSetName='Verify')]
param(
    [Parameter(Mandatory=$true)] [string] $BundlePath,
    [Parameter(Mandatory=$true, ParameterSetName='Apply')] [switch] $Apply,
    [Parameter(Mandatory=$true, ParameterSetName='Verify')] [switch] $VerifyOnly
)
$ErrorActionPreference = 'Stop'

function Get-AcceptanceIdentity {
    return @{
        Commit='1ba55b2c30a8fc8f8783fa60d000b179906aa306'; Run='37145743889'
        Binaries=@{
            gui=@{ Hash='d75f11f7e41f05cd27f06144c3029338898ce5a854120f2ecc1dcc2c3669841e'; Size=[int64]13676032; Level='asInvoker' }
            helper=@{ Hash='0181b66a0c77d9ceee6fc06b50bf4ef169b887a6c2fc8212be99142da6d63747'; Size=[int64]664576; Level='requireAdministrator' }
        }
    }
}
function Assert-AcceptanceProvenance($provenance, $manifest) {
    $identity = Get-AcceptanceIdentity
    if ($provenance.schema_version -ne 1 -or $provenance.source_commit -cne $identity.Commit -or [string]$provenance.workflow_run_id -cne $identity.Run) { throw 'Pinned acceptance commit/run mismatch' }
    foreach ($metadata in @($provenance, $manifest)) {
        if ($metadata.architecture -cne 'x86_64-pc-windows-msvc' -or $metadata.protocol_version -ne 2 -or $metadata.production_status -cne 'NON-PRODUCTION') { throw 'Acceptance architecture/protocol/status mismatch' }
    }
    foreach ($name in @('gui','helper')) {
        $expected = $identity.Binaries[$name]; $record = $provenance.$name; $binary = $manifest.binaries.$name
        if ($record.relative_path -cne "stage/Program Files/BootHop/boothop-$name.exe" -or $record.authenticode_status -cne 'NotSigned' -or
            $record.sha256 -cne $expected.Hash -or $binary.sha256 -cne $expected.Hash -or
            $record.size -ne $expected.Size -or $binary.size -ne $expected.Size -or
            $record.execution_level -cne $expected.Level -or $binary.execution_level -cne $expected.Level -or $binary.protocol_version -ne 2) {
            throw "Pinned $name identity mismatch"
        }
    }
}
function Assert-AcceptanceAcl($acl, [string]$label, [switch]$NoOrdinaryAccess, [switch]$ParentBoundary) {
    $trusted = @('S-1-5-18','S-1-5-32-544')
    # Windows owns the existing Program Files ancestor through TrustedInstaller.
    if ($ParentBoundary) { $trusted += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
    if ($null -eq $acl -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw "$label owner is not trusted" }
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) { throw "$label has a null DACL" }
    # Reject callback/conditional/unknown ACE types rather than guessing access.
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -and $ace.AceType -ne [Security.AccessControl.AceType]::AccessDenied) { throw "$label has an unsupported ACL rule" }
    }
    $writeMask = [int64][Security.AccessControl.FileSystemRights]::Write -bor [int64][Security.AccessControl.FileSystemRights]::Delete -bor
        [int64][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [int64][Security.AccessControl.FileSystemRights]::ChangePermissions -bor [int64][Security.AccessControl.FileSystemRights]::TakeOwnership
    if ($ParentBoundary) {
        # Existing children need protection against removal and ACL takeover;
        # creating an unrelated child in C:\ or ProgramData is harmless here.
        $writeMask = [int64][Security.AccessControl.FileSystemRights]::Delete -bor [int64][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [int64][Security.AccessControl.FileSystemRights]::ChangePermissions -bor [int64][Security.AccessControl.FileSystemRights]::TakeOwnership
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IdentityReference.Value -in $trusted) { continue }
        # CREATOR OWNER applies only to descendants, whose actual owner/ACL
        # is checked separately (including both exclusive candidates).
        if ($rule.IdentityReference.Value -ceq 'S-1-3-0' -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($ParentBoundary -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($NoOrdinaryAccess -and [int64]$rule.FileSystemRights -ne 0) { throw "$label permits ordinary access" }
        if (([int64]$rule.FileSystemRights -band $writeMask) -ne 0) { throw "$label permits ordinary write" }
    }
}
function Assert-AcceptancePathAcl([string]$path, [switch]$NoOrdinaryAccess, [switch]$ParentBoundary) {
    Assert-AcceptanceAcl (Get-Acl -LiteralPath $path) $path -NoOrdinaryAccess:$NoOrdinaryAccess -ParentBoundary:$ParentBoundary
}
function Get-AcceptanceProcessDisposition([string]$image, [string[]]$paths) {
    if ([string]::IsNullOrWhiteSpace($image) -or $image -notmatch '^[A-Za-z]:\\' -or $image -match '(?:^|\\)\.\.(?:\\|$)') { throw 'BootHop process identity uncertain; stop without killing any uncertain process' }
    foreach ($path in $paths) { if ([string]::Equals($image,$path,[StringComparison]::OrdinalIgnoreCase)) { return 'Stop' } }
    return 'Ignore'
}
function Get-AcceptanceProcesses([string[]]$paths) {
    $selected = [Collections.Generic.List[object]]::new()
    try {
        foreach ($name in @('boothop-gui','boothop-helper')) {
            foreach ($process in [Diagnostics.Process]::GetProcessesByName($name)) {
                try {
                    if ($process.HasExited) { $process.Dispose(); continue }
                    # Query through this retained process handle, never reuse a PID.
                    $image = [WindowsFileHandle]::ProcessImagePath($process.Handle)
                    if ((Get-AcceptanceProcessDisposition $image $paths) -ceq 'Stop') { $selected.Add($process) }
                    else { $process.Dispose() }
                } catch {
                    $exited = $false; try { $exited = $process.HasExited } catch { }
                    $process.Dispose()
                    if (-not $exited) { throw 'BootHop process identity uncertain; no uncertain process was killed' }
                }
            }
        }
        return @($selected)
    } catch { foreach ($process in $selected) { $process.Dispose() }; throw }
}
function Stop-AcceptanceProcesses([string[]]$paths) {
    $selected = @(Get-AcceptanceProcesses $paths)
    try {
        # Finish classifying every candidate before stopping the known pair.
        foreach ($process in $selected) {
            if (-not $process.HasExited) { $process.Kill(); if (-not $process.WaitForExit(10000)) { throw 'Fixed-path BootHop process did not stop' } }
        }
    } finally { foreach ($process in $selected) { $process.Dispose() } }
}
function Assert-AcceptanceProcessesStopped([string[]]$paths) {
    $selected = @(Get-AcceptanceProcesses $paths)
    try {
        foreach ($process in $selected) { if (-not $process.HasExited) { throw 'Fixed-path BootHop process restarted; stop without another kill or retry' } }
    } finally { foreach ($process in $selected) { $process.Dispose() } }
}
function Write-AcceptanceCopy($held, [string]$destination, [string]$hash, [int64]$size, [scriptblock]$OnCreated = $null) {
    $output = [IO.FileStream]::new($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { if ($null -ne $OnCreated) { & $OnCreated $destination }; Reset-Held $held; $held.Stream.CopyTo($output); $output.Flush($true) }
    finally { $output.Dispose(); Reset-Held $held }
    $copy = Open-HeldFileResource $destination 'acceptance copy' $destination
    try {
        if ($copy.Held.Stream.Length -ne $size -or (Get-HeldHash $copy.Held) -cne $hash) { throw 'Acceptance copy hash/size mismatch' }
    } finally { Close-Held $copy }
}
function Invoke-AcceptanceReplace($entry, $resources, $replaced, [scriptblock]$CheckAcl) {
    & $CheckAcl $entry.Path; & $CheckAcl $entry.Temporary
    Close-Held $entry.Existing
    [IO.File]::Replace($entry.Temporary,$entry.Path,$null)
    $replaced.Add($entry.Name)
    $installed = Add-HeldResource $resources (Open-HeldFileResource $entry.Path 'installed acceptance PE' $entry.Path)
    & $CheckAcl $entry.Path
    if ($installed.Held.Stream.Length -ne $entry.Expected.Size -or (Get-HeldHash $installed.Held) -cne $entry.Expected.Hash) { throw "Installed $($entry.Name) readback mismatch" }
}
function Get-AcceptanceDataBaseline([string]$path, $resources) {
    $baseline = [Collections.Generic.List[object]]::new()
    $pending = [Collections.Generic.Stack[string]]::new(); $pending.Push($path)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $pins = Open-HeldDirectoryPins $directory 'protected data directory' $directory
        [void](Add-HeldResource $resources $pins)
        Assert-AcceptancePathAcl $directory -NoOrdinaryAccess
        $baseline.Add([pscustomobject]@{Path=$directory; Acl=(Get-Acl -LiteralPath $directory).Sddl; Held=$null; Hash=$null})
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected data contains a reparse point' }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
            else {
                $file = Open-HeldFileResource $item.FullName 'protected data file' $item.FullName
                [void](Add-HeldResource $resources $file)
                Assert-AcceptancePathAcl $item.FullName -NoOrdinaryAccess
                $baseline.Add([pscustomobject]@{Path=$item.FullName; Acl=(Get-Acl -LiteralPath $item.FullName).Sddl; Held=$file.Held; Hash=(Get-HeldHash $file.Held)})
            }
        }
    }
    return @($baseline)
}
function Assert-AcceptanceDataBaseline($baseline) {
    foreach ($entry in $baseline) {
        Assert-AcceptancePathAcl $entry.Path -NoOrdinaryAccess
        if ((Get-Acl -LiteralPath $entry.Path).Sddl -cne $entry.Acl) { throw 'Protected data ACL changed; stop' }
        if ($null -ne $entry.Held -and (Get-HeldHash $entry.Held) -cne $entry.Hash) { throw 'Protected data bytes changed; stop' }
    }
    # Detect additions/removals as well as byte/ACL changes. Existing handles
    # prohibit concurrent changes to the data files while this check runs.
    $expectedPaths = @($baseline | ForEach-Object { $_.Path })
    $count = 1
    foreach ($directory in @($baseline | Where-Object { $null -eq $_.Held })) {
        foreach ($child in Get-ChildItem -LiteralPath $directory.Path -Force) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $child.FullName -cnotin $expectedPaths) { throw 'Protected data entries changed; stop' }
            $count++
        }
    }
    if ($count -ne $baseline.Count) { throw 'Protected data entries changed; stop' }
}

if ([bool]$Apply -eq [bool]$VerifyOnly) { throw 'Specify exactly one of -Apply or -VerifyOnly with a true switch value' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows is required' }
if ($Apply) {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Apply requires an already elevated administrator shell' }
}
. (Join-Path $PSScriptRoot 'held.ps1')
$resources = New-HeldResourceSet
$oldFiles = [Collections.Generic.List[object]]::new()
$temporaries = [Collections.Generic.List[string]]::new()
$replaced = [Collections.Generic.List[string]]::new()
try {
    if ($BundlePath -notmatch '^[A-Za-z]:\\') { throw 'BundlePath must be an absolute local Windows drive path' }
    $bundle = [IO.Path]::GetFullPath($BundlePath)
    [void](Add-HeldResource $resources (Open-HeldDirectoryPins $bundle 'acceptance bundle' $bundle))
    $stage = Join-Path $bundle 'stage'
    [void](Add-HeldResource $resources (Open-HeldDirectoryPins $stage 'acceptance stage' $stage))
    $source = @{}
    # Keep all audited inputs held across check-package, metadata validation,
    # copying and readback, preventing a hash/check/copy race.
    foreach ($relative in @('manifest.json','NON-PRODUCTION.txt','Program Files\BootHop\boothop-gui.exe','Program Files\BootHop\boothop-helper.exe','Program Files\BootHop\boothop-gui.manifest','Program Files\BootHop\boothop-helper.manifest','ProgramData\BootHop\.directory-policy.json')) {
        $path = Join-Path $stage $relative
        $source[$relative] = Add-HeldResource $resources (Open-HeldFileResource $path "stage $relative" $path)
    }
    $provenancePath = Join-Path $bundle 'provenance.json'
    $provenanceFile = Add-HeldResource $resources (Open-HeldFileResource $provenancePath 'provenance' $provenancePath)
    & (Join-Path $PSScriptRoot 'check-package.ps1') -StagePath $stage
    $manifest = Read-HeldText $source['manifest.json'].Held | ConvertFrom-Json
    $provenance = Read-HeldText $provenanceFile.Held | ConvertFrom-Json
    Assert-AcceptanceProvenance $provenance $manifest
    $identity = Get-AcceptanceIdentity
    # Literal existing-layout contract: no environment expansion or install-root override.
    $install = 'C:\Program Files\BootHop'; $data = 'C:\ProgramData\BootHop'
    foreach ($directory in @($install,$data)) {
        [void](Add-HeldResource $resources (Open-HeldDirectoryPins $directory 'existing acceptance layout' $directory))
    }
    foreach ($ancestor in @('C:\','C:\Program Files','C:\ProgramData')) { Assert-AcceptancePathAcl $ancestor -ParentBoundary }
    Assert-AcceptancePathAcl $install
    $baseline = @(Get-AcceptanceDataBaseline $data $resources)
    $entries = @()
    foreach ($name in @('gui','helper')) {
        $path = Join-Path $install "boothop-$name.exe"
        $existing = Open-HeldFileResource $path 'existing acceptance PE' $path; $oldFiles.Add($existing)
        Assert-AcceptancePathAcl $path
        $expected = $identity.Binaries[$name]; $inputFile = $source["Program Files\BootHop\boothop-$name.exe"].Held
        if ($inputFile.Stream.Length -ne $expected.Size -or (Get-HeldHash $inputFile) -cne $expected.Hash) { throw "Pinned $name bytes mismatch" }
        $entries += [pscustomobject]@{Name=$name; Path=$path; Input=$inputFile; Expected=$expected; Existing=$existing; Temporary=$null}
    }
    if ($VerifyOnly) {
        foreach ($entry in $entries) {
            if ($entry.Existing.Held.Stream.Length -ne $entry.Expected.Size -or (Get-HeldHash $entry.Existing.Held) -cne $entry.Expected.Hash) { throw "Installed $($entry.Name) hash/size differs from pinned artifact" }
        }
        Assert-AcceptanceDataBaseline $baseline
        Write-Output 'Acceptance verification passed: pinned pair and existing protected ACLs. No processes stopped or files written.'
    } else {
        Write-Warning 'NON-PRODUCTION acceptance update: each replacement is atomic, but the pair is not. Keep the GUI and helper closed until BOTH installed hashes and ACLs are verified. Failure means STOP; no automatic rollback or retry.'
        Stop-AcceptanceProcesses @($entries | ForEach-Object { $_.Path })
        # Prepare and flush both candidates before changing either installed PE.
        foreach ($entry in $entries) {
            $entry.Temporary = Join-Path $install ('.boothop-acceptance-' + [guid]::NewGuid().ToString('N') + '.tmp')
            # Register only after exclusive creation, avoiding deletion of an
            # unrelated pre-existing name even in the event of a collision.
            Write-AcceptanceCopy $entry.Input $entry.Temporary $entry.Expected.Hash $entry.Expected.Size {
                param($created)
                $temporaries.Add($created); Assert-AcceptancePathAcl $created
            }
        }
        Assert-AcceptanceDataBaseline $baseline
        foreach ($entry in $entries) {
            Assert-AcceptanceProcessesStopped @($entries | ForEach-Object { $_.Path })
            Assert-AcceptancePathAcl $install
            Invoke-AcceptanceReplace $entry $resources $replaced { param($path) Assert-AcceptancePathAcl $path }
        }
        Assert-AcceptanceDataBaseline $baseline
        Write-Output 'Acceptance update passed: BOTH pinned files verified; existing protected data remained held and unchanged. No BootHop PE was executed.'
    }
} catch {
    throw "Acceptance STOP. Replaced files: [$($replaced -join ', ')]. Keep BootHop closed; do not automatically retry or roll back. $($_.Exception.Message)"
} finally {
    foreach ($existing in $oldFiles) { Close-Held $existing }
    Close-HeldResourceSet $resources
    # Only exclusive sibling candidates created by this invocation are removed.
    foreach ($temporary in $temporaries) { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
