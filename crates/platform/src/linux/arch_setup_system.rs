//! Concrete setup policy over an injected host boundary. The normal helper never constructs it.
use std::path::{Path, PathBuf};

use boothop_core::{BootId, Error, arch_uki_load_option, serialize_load_option};

use super::{
    arch_identity::{IDENTITY_MARKER_PATH, InstalledIdentity},
    arch_setup::{ArchSetupBackend, ObservationError, POST_HOOK, PUBLISHER, SetupProblem},
    arch_uki::{
        ArchSetupSource, CmdlineSource, EspInfo, PackageHookRoute, SecureBootState, SetupError,
        UkiPlan, is_safe_flavor, plan_arch_uki,
    },
    setup_firmware::{SetupFirmware, decode_boot_order},
};

const PRESETS: &str = "/etc/mkinitcpio.d";
const MODULES: &str = "/usr/lib/modules";
const PACKAGE_HOOK: &str = "/usr/share/libalpm/hooks/90-mkinitcpio-install.hook";
const PACKAGE_SCRIPT: &str = "/usr/share/libalpm/scripts/mkinitcpio";
const MKINITCPIO: &str = "/usr/bin/mkinitcpio";
const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const BOOT_ORDER: &str = "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const BOOT_NEXT: &str = "BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const SECURE_BOOT: &str = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const MAX_PRESET: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u64,
    pub size: u64,
}

/// The only I/O boundary. Every native method checks fixed-path parents, avoids symlinks,
/// and makes one mutation attempt. Tests inject this trait and never construct NativeArchCalls.
pub trait ArchSystemCalls {
    fn metadata(&self, path: &Path) -> Result<Option<HostMetadata>, i32>;
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, i32>;
    fn list(&self, path: &Path) -> Result<Vec<String>, i32>;
    fn replace_if_exact(&mut self, path: &Path, old: &[u8], new: &[u8]) -> Result<(), i32>;
    fn create_exclusive(&mut self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), i32>;
    fn ensure_directory(&mut self, path: &Path) -> Result<(), i32>;
    fn remove_regular(&mut self, path: &Path) -> Result<(), i32>;
    fn run(&mut self, command: &Path, args: &[&str], initial: bool) -> Result<(), i32>;
    fn esp_info(&self) -> Result<EspInfo, i32>;
    fn attest_package_route(&self, hook: &[u8], script: &[u8]) -> Result<bool, i32>;
    fn efi_names(&mut self) -> Result<Vec<Vec<u8>>, i32>;
    /// Returns the efivarfs attribute word separately from the variable payload.
    fn efi_read(&self, name: &[u8]) -> Result<Option<(u32, Vec<u8>)>, i32>;
    fn efi_create(&mut self, id: BootId, option: &[u8]) -> Result<(), i32>;
    fn efi_replace_order(&mut self, order: &[u8]) -> Result<(), i32>;
    fn save_marker(&mut self, identity: &InstalledIdentity) -> Result<(), i32>;
}

pub struct SystemArchSetupBackend<C: ArchSystemCalls> {
    calls: C,
    selected: Option<String>,
}

impl<C: ArchSystemCalls> SystemArchSetupBackend<C> {
    pub fn new(calls: C) -> Self {
        Self {
            calls,
            selected: None,
        }
    }
    pub fn calls(&self) -> &C {
        &self.calls
    }
    pub fn calls_mut(&mut self) -> &mut C {
        &mut self.calls
    }
    fn trusted_file(&self, path: &Path, exact_mode: Option<u32>) -> Result<HostMetadata, i32> {
        let meta = self.calls.metadata(path)?.ok_or(2)?;
        if meta.uid != 0
            || meta.gid != 0
            || meta.links != 1
            || meta.mode & 0o170000 != 0o100000
            || meta.mode & 0o022 != 0
            || exact_mode.is_some_and(|mode| meta.mode & 0o777 != mode)
        {
            return Err(1);
        }
        Ok(meta)
    }
    fn trusted_directory(&self, path: &Path) -> Result<(), i32> {
        let meta = self.calls.metadata(path)?.ok_or(2)?;
        if meta.uid != 0
            || meta.gid != 0
            || meta.mode & 0o170000 != 0o040000
            || meta.mode & 0o022 != 0
        {
            return Err(1);
        }
        Ok(())
    }
    fn read_trusted(&self, path: &Path, limit: usize) -> Result<Vec<u8>, i32> {
        let meta = self.trusted_file(path, None)?;
        if meta.size > limit as u64 {
            return Err(27);
        }
        let bytes = self.calls.read(path)?.ok_or(2)?;
        if bytes.len() as u64 != meta.size || self.calls.metadata(path)? != Some(meta) {
            return Err(5);
        }
        Ok(bytes)
    }
    fn efi_payload(&mut self, name: &[u8], attr: u32) -> Result<Option<Vec<u8>>, Error> {
        let value = self.calls.efi_read(name).map_err(platform_read)?;
        match value {
            None => Ok(None),
            Some((actual, bytes)) if actual == attr && bytes.len() <= 1_048_576 => Ok(Some(bytes)),
            _ => Err(Error::UnsupportedFormat),
        }
    }
    fn hook_bytes(plan: &UkiPlan) -> Result<Vec<u8>, i32> {
        let stage = plan.staged_uki_path().to_str().ok_or(22)?;
        if stage.contains('\0') || stage.contains('\n') {
            return Err(22);
        }
        let quoted = stage.replace('\'', "'\\''");
        Ok(format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nmode=--update\nif [[ \"${{BOOTHOP_ARCH_INITIAL:-}}\" == 1 ]]; then mode=--initial; fi\nexec {PUBLISHER} \"$mode\" '{quoted}' \"$@\"\n"
        ).into_bytes())
    }
}

fn platform_read(raw_code: i32) -> Error {
    Error::PlatformIo {
        operation: boothop_core::PlatformOperation::Read,
        raw_code,
    }
}
fn platform_write(raw_code: i32) -> Error {
    Error::PlatformIo {
        operation: boothop_core::PlatformOperation::Write,
        raw_code,
    }
}
fn backend(_: i32) -> SetupProblem {
    SetupProblem::Backend
}
fn unknown(_: i32) -> ObservationError {
    ObservationError
}
fn boot_name(id: BootId) -> Vec<u8> {
    format!("Boot{:04X}-{GUID}", id.0).into_bytes()
}
fn trusted_text(bytes: Vec<u8>) -> Result<String, SetupError> {
    String::from_utf8(bytes).map_err(|_| SetupError::SourceUnavailable)
}
fn contains_line(text: &str, line: &str) -> bool {
    text.lines().any(|candidate| candidate.trim() == line)
}

/// Only the inspected Arch package route is supported. Unknown script changes stop setup.
pub fn route_is_supported(hook: &str, script: &str) -> bool {
    contains_line(hook, "Exec = /usr/share/libalpm/scripts/mkinitcpio install")
        && contains_line(hook, "NeedsTargets")
        && contains_line(hook, "When = PostTransaction")
        && contains_line(hook, "Target = usr/lib/modules/*/vmlinuz")
        && contains_line(script, "add_pkgbase_to_args \"$pkgbase\"")
        && contains_line(script, "args+=(-p \"$pkgbase\")")
        && contains_line(script, "args=(-P)")
        && contains_line(script, "mkinitcpio \"${args[@]}\"")
        && !hook.contains("--nopost")
        && !script.contains("--nopost")
}

impl<C: ArchSystemCalls> ArchSetupSource for SystemArchSetupBackend<C> {
    fn installed_flavors(&self) -> Result<Vec<String>, SetupError> {
        let mut flavors = Vec::new();
        for name in self
            .calls
            .list(Path::new(PRESETS))
            .map_err(|_| SetupError::SourceUnavailable)?
        {
            let Some(flavor) = name.strip_suffix(".preset") else {
                continue;
            };
            if !is_safe_flavor(flavor) {
                return Err(SetupError::UnsupportedPreset);
            }
            self.trusted_file(&Path::new(PRESETS).join(&name), None)
                .map_err(|_| SetupError::UnsupportedPreset)?;
            flavors.push(flavor.to_owned());
        }
        Ok(flavors)
    }
    fn cmdline_source(&self) -> Result<CmdlineSource, SetupError> {
        let path = PathBuf::from("/etc/kernel/cmdline");
        match self
            .calls
            .metadata(&path)
            .map_err(|_| SetupError::SourceUnavailable)?
        {
            None => Ok(CmdlineSource::Missing),
            Some(_) => {
                let bytes = self
                    .read_trusted(&path, 4096)
                    .map_err(|_| SetupError::UnsupportedCmdline)?;
                if bytes.is_empty()
                    || bytes.contains(&0)
                    || bytes.iter().all(u8::is_ascii_whitespace)
                {
                    return Ok(CmdlineSource::Dynamic);
                }
                Ok(CmdlineSource::Persistent(path))
            }
        }
    }
    fn esp_info(&self) -> Result<EspInfo, SetupError> {
        self.calls
            .esp_info()
            .map_err(|_| SetupError::UnsupportedEsp)
    }
    fn secure_boot_state(&self) -> Result<SecureBootState, SetupError> {
        match self.calls.efi_read(SECURE_BOOT.as_bytes()) {
            Ok(Some((6, bytes))) if bytes == [0] => Ok(SecureBootState::Disabled),
            Ok(Some((6, bytes))) if bytes == [1] => Ok(SecureBootState::Enabled),
            _ => Ok(SecureBootState::Unknown),
        }
    }
    fn package_hook_route(&self) -> Result<Option<PackageHookRoute>, SetupError> {
        let flavor = self
            .selected
            .as_ref()
            .ok_or(SetupError::FlavorSelectionRequired)?;
        let hook = trusted_text(
            self.read_trusted(Path::new(PACKAGE_HOOK), 16 * 1024)
                .map_err(|_| SetupError::UnknownPackageHookRoute)?,
        )?;
        let script = trusted_text(
            self.read_trusted(Path::new(PACKAGE_SCRIPT), 128 * 1024)
                .map_err(|_| SetupError::UnknownPackageHookRoute)?,
        )?;
        if !route_is_supported(&hook, &script)
            || !self
                .calls
                .attest_package_route(hook.as_bytes(), script.as_bytes())
                .map_err(|_| SetupError::UnknownPackageHookRoute)?
        {
            return Ok(None);
        }
        let mut matches = 0;
        for dir in self
            .calls
            .list(Path::new(MODULES))
            .map_err(|_| SetupError::UnknownPackageHookRoute)?
        {
            let path = Path::new(MODULES).join(&dir).join("pkgbase");
            let Ok(bytes) = self.read_trusted(&path, 128) else {
                continue;
            };
            if bytes == format!("{flavor}\n").as_bytes() {
                self.trusted_file(&Path::new(MODULES).join(&dir).join("vmlinuz"), None)
                    .map_err(|_| SetupError::UnknownPackageHookRoute)?;
                matches += 1;
            }
        }
        if matches != 1 {
            return Ok(None);
        }
        Ok(Some(PackageHookRoute {
            preset: flavor.clone(),
            post_hooks_enabled: true,
        }))
    }
}

impl<C: ArchSystemCalls> SetupFirmware for SystemArchSetupBackend<C> {
    fn enumerate_variables(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        self.calls.efi_names().map_err(platform_read)
    }
    fn read_variable(&mut self, exact_name: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.efi_payload(exact_name, 7)
    }
    fn create_boot_entry_exclusive(&mut self, id: BootId, option: &[u8]) -> Result<(), Error> {
        self.calls.efi_create(id, option).map_err(platform_write)
    }
    fn replace_boot_order(&mut self, order: &[u8]) -> Result<(), Error> {
        self.calls.efi_replace_order(order).map_err(platform_write)
    }
}

impl<C: ArchSystemCalls> ArchSetupBackend for SystemArchSetupBackend<C> {
    type Firmware = Self;
    fn plan(&mut self, flavor: &str) -> Result<UkiPlan, SetupError> {
        self.selected = Some(flavor.to_owned());
        plan_arch_uki(flavor, self)
    }
    fn firmware(&mut self) -> &mut Self::Firmware {
        self
    }
    fn verify_initial_absence(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem> {
        if self
            .calls
            .metadata(Path::new(IDENTITY_MARKER_PATH))
            .map_err(backend)?
            .is_some()
            || self
                .calls
                .metadata(plan.final_uki_path())
                .map_err(backend)?
                .is_some()
        {
            return Err(SetupProblem::Backend);
        }
        self.trusted_directory(plan.esp_mount_point())
            .map_err(backend)?;
        let next = self
            .read_variable(BOOT_NEXT.as_bytes())
            .map_err(SetupProblem::Firmware)?;
        if next.is_some() {
            return Err(SetupProblem::Firmware(Error::BootNextConflict));
        }
        let order = self
            .read_variable(BOOT_ORDER.as_bytes())
            .map_err(SetupProblem::Firmware)?
            .ok_or(SetupProblem::Firmware(Error::TargetMissing))?;
        if decode_boot_order(&order)
            .map_err(SetupProblem::Firmware)?
            .first()
            != Some(&BootId(0))
        {
            return Err(SetupProblem::Backend);
        }
        let option = serialize_load_option(
            &arch_uki_load_option(plan.esp_identity()).map_err(SetupProblem::Firmware)?,
        )
        .map_err(SetupProblem::Firmware)?;
        for name in self.enumerate_variables().map_err(SetupProblem::Firmware)? {
            if name.len() == 45
                && name.starts_with(b"Boot")
                && name[8] == b'-'
                && name[9..] == *GUID.as_bytes()
                && self
                    .read_variable(&name)
                    .map_err(SetupProblem::Firmware)?
                    .as_deref()
                    == Some(&option)
            {
                return Err(SetupProblem::Backend);
            }
        }
        Ok(())
    }
    fn verify_publisher(&mut self) -> Result<(), SetupProblem> {
        self.trusted_file(Path::new(PUBLISHER), Some(0o755))
            .map_err(backend)?;
        Ok(())
    }
    fn read_preset(&mut self, plan: &UkiPlan) -> Result<String, SetupProblem> {
        self.trusted_file(plan.preset_path(), Some(0o644))
            .map_err(backend)?;
        let bytes = self
            .read_trusted(plan.preset_path(), MAX_PRESET)
            .map_err(backend)?;
        String::from_utf8(bytes).map_err(|_| SetupProblem::Backend)
    }
    fn write_preset_if_exact(
        &mut self,
        plan: &UkiPlan,
        old: &str,
        new: &str,
    ) -> Result<(), SetupProblem> {
        self.calls
            .replace_if_exact(plan.preset_path(), old.as_bytes(), new.as_bytes())
            .map_err(backend)
    }
    fn install_fixed_hook(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem> {
        self.trusted_directory(Path::new("/etc/initcpio/post"))
            .map_err(backend)?;
        let bytes = Self::hook_bytes(plan).map_err(backend)?;
        self.calls
            .create_exclusive(Path::new(POST_HOOK), &bytes, 0o755)
            .map_err(backend)
    }
    fn clear_stage(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem> {
        let directory = plan
            .staged_uki_path()
            .parent()
            .ok_or(SetupProblem::Backend)?;
        self.trusted_directory(plan.esp_mount_point())
            .map_err(backend)?;
        self.trusted_directory(&plan.esp_mount_point().join("EFI"))
            .map_err(backend)?;
        self.calls.ensure_directory(directory).map_err(backend)?;
        self.trusted_directory(directory).map_err(backend)?;
        if self
            .calls
            .metadata(plan.staged_uki_path())
            .map_err(backend)?
            .is_some()
        {
            self.trusted_file(plan.staged_uki_path(), None)
                .map_err(backend)?;
            self.calls
                .remove_regular(plan.staged_uki_path())
                .map_err(backend)?;
        }
        Ok(())
    }
    fn build_initial(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem> {
        self.calls
            .run(Path::new(MKINITCPIO), &["-p", plan.flavor()], true)
            .map_err(backend)
    }
    fn inspect_published(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem> {
        let bytes = self
            .read_trusted(plan.final_uki_path(), 512 * 1024 * 1024)
            .map_err(backend)?;
        if bytes.len() < 512
            || !bytes.starts_with(b"MZ")
            || bytes.get(0x3c..0x40).and_then(|offset| {
                let array: [u8; 4] = offset.try_into().ok()?;
                let start = u32::from_le_bytes(array) as usize;
                bytes.get(start..start.checked_add(4)?)
            }) != Some(b"PE\0\0")
            || self
                .calls
                .metadata(plan.staged_uki_path())
                .map_err(backend)?
                .is_some()
        {
            return Err(SetupProblem::Backend);
        }
        Ok(())
    }
    fn save_identity(&mut self, identity: &InstalledIdentity) -> Result<(), SetupProblem> {
        self.calls.save_marker(identity).map_err(backend)
    }
    fn observe_preset_stanza(
        &mut self,
        plan: Option<&UkiPlan>,
    ) -> Result<Option<String>, ObservationError> {
        let Some(plan) = plan else { return Ok(None) };
        let bytes = self
            .calls
            .read(plan.preset_path())
            .map_err(unknown)?
            .ok_or(ObservationError)?;
        let text = String::from_utf8(bytes).map_err(|_| ObservationError)?;
        let stanza = text
            .lines()
            .filter(|line| line.contains("boothop"))
            .take(4)
            .collect::<Vec<_>>()
            .join("\n");
        Ok((!stanza.is_empty()).then_some(stanza))
    }
    fn observe_hook_exact(&mut self, plan: Option<&UkiPlan>) -> Result<bool, ObservationError> {
        let Some(plan) = plan else { return Ok(false) };
        let expected = Self::hook_bytes(plan).map_err(unknown)?;
        let Some(meta) = self.calls.metadata(Path::new(POST_HOOK)).map_err(unknown)? else {
            return Ok(false);
        };
        if meta.uid != 0 || meta.gid != 0 || meta.mode != 0o100755 || meta.links != 1 {
            return Ok(false);
        }
        let actual = self.calls.read(Path::new(POST_HOOK)).map_err(unknown)?;
        Ok(actual.as_deref() == Some(expected.as_slice()))
    }
    fn observe_artifact(&mut self, plan: Option<&UkiPlan>) -> Result<bool, ObservationError> {
        let Some(plan) = plan else { return Ok(false) };
        Ok(self
            .calls
            .metadata(plan.final_uki_path())
            .map_err(unknown)?
            .is_some())
    }
    fn observe_entry_exact(&mut self, id: BootId, option: &[u8]) -> Result<bool, ObservationError> {
        Ok(self
            .read_variable(&boot_name(id))
            .map_err(|_| ObservationError)?
            .as_deref()
            == Some(option))
    }
    fn observe_order(&mut self) -> Result<Vec<BootId>, ObservationError> {
        decode_boot_order(
            &self
                .read_variable(BOOT_ORDER.as_bytes())
                .map_err(|_| ObservationError)?
                .ok_or(ObservationError)?,
        )
        .map_err(|_| ObservationError)
    }
    fn observe_next(&mut self) -> Result<Option<BootId>, ObservationError> {
        self.read_variable(BOOT_NEXT.as_bytes())
            .map_err(|_| ObservationError)?
            .map(|bytes| {
                let pair: [u8; 2] = bytes.try_into().map_err(|_| ObservationError)?;
                Ok(BootId(u16::from_le_bytes(pair)))
            })
            .transpose()
    }
}
