#![cfg(target_os = "linux")]

use boothop_core::{BootId, GptEspIdentity};
use boothop_platform::linux::{
    arch_identity::InstalledIdentity,
    arch_setup::{Observed, SetupIntent, SetupStage, run_arch_setup},
    arch_setup_system::{
        ArchSystemCalls, HostMetadata, SystemArchSetupBackend, route_is_supported,
    },
    arch_uki::EspInfo,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const PRESET: &str = "PRESETS=('default' 'fallback')\nALL_kver='/boot/vmlinuz-linux'\ndefault_image='/boot/initramfs-linux.img'\nfallback_image='/boot/initramfs-linux-fallback.img'\n";
const HOOK: &str = "When = PostTransaction\nTarget = usr/lib/modules/*/vmlinuz\nExec = /usr/share/libalpm/scripts/mkinitcpio install\nNeedsTargets\n";
const SCRIPT: &str = "add_pkgbase_to_args \"$pkgbase\"\nargs+=(-p \"$pkgbase\")\nargs=(-P)\nmkinitcpio \"${args[@]}\"\n";
fn meta(mode: u32, len: usize) -> HostMetadata {
    HostMetadata {
        uid: 0,
        gid: 0,
        mode,
        links: 1,
        size: len as u64,
    }
}
fn key(stem: &str) -> Vec<u8> {
    format!("{stem}-{GUID}").into_bytes()
}
fn uki() -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes
}
struct Fake {
    files: HashMap<PathBuf, Vec<u8>>,
    modes: HashMap<PathBuf, u32>,
    lists: HashMap<PathBuf, Vec<String>>,
    vars: HashMap<Vec<u8>, (u32, Vec<u8>)>,
    actions: Vec<String>,
    marker: Option<InstalledIdentity>,
    fail: Option<&'static str>,
    attested: bool,
}
impl Fake {
    fn new() -> Self {
        let mut value = Self {
            files: HashMap::new(),
            modes: HashMap::new(),
            lists: HashMap::new(),
            vars: HashMap::new(),
            actions: Vec::new(),
            marker: None,
            fail: None,
            attested: true,
        };
        for path in [
            "/boot",
            "/boot/EFI",
            "/boot/EFI/BootHop",
            "/etc/initcpio/post",
        ] {
            value.modes.insert(path.into(), 0o40755);
        }
        for (path, content, mode) in [
            (
                "/etc/mkinitcpio.d/linux.preset",
                PRESET.as_bytes(),
                0o100644,
            ),
            (
                "/etc/kernel/cmdline",
                b"root=UUID=example rw\n".as_slice(),
                0o100644,
            ),
            (
                "/usr/share/libalpm/hooks/90-mkinitcpio-install.hook",
                HOOK.as_bytes(),
                0o100644,
            ),
            (
                "/usr/share/libalpm/scripts/mkinitcpio",
                SCRIPT.as_bytes(),
                0o100755,
            ),
            (
                "/usr/lib/modules/6.1/pkgbase",
                b"linux\n".as_slice(),
                0o100644,
            ),
            (
                "/usr/lib/modules/6.1/vmlinuz",
                b"kernel".as_slice(),
                0o100644,
            ),
            (
                "/usr/lib/boothop/boothop-uki-publish",
                b"publisher".as_slice(),
                0o100755,
            ),
        ] {
            value.files.insert(path.into(), content.to_vec());
            value.modes.insert(path.into(), mode);
        }
        value
            .lists
            .insert("/etc/mkinitcpio.d".into(), vec!["linux.preset".into()]);
        value
            .lists
            .insert("/usr/lib/modules".into(), vec!["6.1".into()]);
        value.vars.insert(key("SecureBoot"), (6, vec![0]));
        value.vars.insert(
            key("BootOrder"),
            (7, [0_u16.to_le_bytes(), 7_u16.to_le_bytes()].concat()),
        );
        value.vars.insert(key("Boot0000"), (7, b"grub".to_vec()));
        value.vars.insert(key("Boot0007"), (7, b"windows".to_vec()));
        value
    }
    fn action(&mut self, name: &str) -> Result<(), i32> {
        self.actions.push(name.to_owned());
        if self.fail == Some(name) {
            Err(5)
        } else {
            Ok(())
        }
    }
}
impl ArchSystemCalls for Fake {
    fn metadata(&self, path: &Path) -> Result<Option<HostMetadata>, i32> {
        Ok(self
            .modes
            .get(path)
            .map(|mode| meta(*mode, self.files.get(path).map_or(0, Vec::len))))
    }
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, i32> {
        Ok(self.files.get(path).cloned())
    }
    fn list(&self, path: &Path) -> Result<Vec<String>, i32> {
        self.lists.get(path).cloned().ok_or(2)
    }
    fn replace_if_exact(&mut self, path: &Path, old: &[u8], new: &[u8]) -> Result<(), i32> {
        self.action("preset")?;
        if self.files.get(path).map(Vec::as_slice) != Some(old) {
            return Err(16);
        }
        self.files.insert(path.into(), new.to_vec());
        Ok(())
    }
    fn create_exclusive(&mut self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), i32> {
        self.action("hook")?;
        if self.files.contains_key(path) {
            return Err(17);
        }
        self.files.insert(path.into(), bytes.to_vec());
        self.modes.insert(path.into(), 0o100000 | mode);
        Ok(())
    }
    fn ensure_directory(&mut self, path: &Path) -> Result<(), i32> {
        self.modes.entry(path.into()).or_insert(0o40755);
        Ok(())
    }
    fn remove_regular(&mut self, path: &Path) -> Result<(), i32> {
        self.action("clear")?;
        self.files.remove(path);
        self.modes.remove(path);
        Ok(())
    }
    fn run(&mut self, command: &Path, args: &[&str], initial: bool) -> Result<(), i32> {
        assert_eq!(command.to_str(), Some("/usr/bin/mkinitcpio"));
        assert_eq!(args, ["-p", "linux"]);
        assert!(initial);
        self.action("mkinitcpio")?;
        self.files
            .insert("/boot/EFI/BootHop/arch.efi".into(), uki());
        self.modes
            .insert("/boot/EFI/BootHop/arch.efi".into(), 0o100644);
        Ok(())
    }
    fn esp_info(&self) -> Result<EspInfo, i32> {
        Ok(EspInfo {
            mount_point: "/boot".into(),
            filesystem: "vfat".into(),
            is_mounted: true,
            is_efi_system_partition: true,
            gpt_identity: Some(GptEspIdentity {
                partition_number: 1,
                start_lba: 2048,
                size_lba: 1_048_576,
                guid_uefi_bytes: [0x11; 16],
            }),
        })
    }
    fn attest_package_route(&self, _: &[u8], _: &[u8]) -> Result<bool, i32> {
        Ok(self.attested)
    }
    fn efi_names(&mut self) -> Result<Vec<Vec<u8>>, i32> {
        Ok(self.vars.keys().cloned().collect())
    }
    fn efi_read(&self, name: &[u8]) -> Result<Option<(u32, Vec<u8>)>, i32> {
        Ok(self.vars.get(name).cloned())
    }
    fn efi_create(&mut self, id: BootId, option: &[u8]) -> Result<(), i32> {
        if self.fail == Some("entry_after_write") {
            self.actions.push("entry".into());
            self.vars.insert(key("Boot0001"), (7, option.to_vec()));
            return Err(5);
        }
        self.action("entry")?;
        assert_eq!(id, BootId(1));
        self.vars.insert(key("Boot0001"), (7, option.to_vec()));
        Ok(())
    }
    fn efi_replace_order(&mut self, order: &[u8]) -> Result<(), i32> {
        if self.fail == Some("order_after_write") {
            self.actions.push("order".into());
            self.vars.insert(key("BootOrder"), (7, order.to_vec()));
            return Err(5);
        }
        self.action("order")?;
        self.vars.insert(key("BootOrder"), (7, order.to_vec()));
        Ok(())
    }
    fn save_marker(&mut self, identity: &InstalledIdentity) -> Result<(), i32> {
        self.action("marker")?;
        self.marker = Some(*identity);
        Ok(())
    }
}

#[test]
fn accepted_arch_route_and_hook_contract_are_exact() {
    assert!(route_is_supported(HOOK, SCRIPT));
    assert!(!route_is_supported(HOOK, &format!("{SCRIPT}\n--nopost")));
    assert!(!route_is_supported(
        &HOOK.replace("NeedsTargets", ""),
        SCRIPT
    ));
    assert!(!route_is_supported(
        HOOK,
        &SCRIPT.replace("args+=(-p \"$pkgbase\")", "")
    ));
}
#[test]
fn injected_system_adapter_runs_full_order_and_fixed_hook_without_host_io() {
    let mut backend = SystemArchSetupBackend::new(Fake::new());
    let identity = run_arch_setup(SetupIntent::new("linux".into()), &mut backend).unwrap();
    let fake = backend.calls();
    assert_eq!(identity.boot_id(), BootId(1));
    assert_eq!(fake.marker, Some(identity));
    assert_eq!(
        fake.actions,
        ["preset", "hook", "mkinitcpio", "entry", "order", "marker"]
    );
    assert_eq!(fake.vars[&key("BootOrder")].1, vec![0, 0, 7, 0, 1, 0]);
    assert_eq!(fake.vars[&key("Boot0000")].1, b"grub");
    let hook = String::from_utf8(
        fake.files
            .iter()
            .find(|(path, _)| path.to_str() == Some("/etc/initcpio/post/boothop-uki"))
            .unwrap()
            .1
            .clone(),
    )
    .unwrap();
    assert!(hook.contains("/usr/lib/boothop/boothop-uki-publish"));
    assert!(hook.contains("mode=--update"));
    assert!(hook.contains("BOOTHOP_ARCH_INITIAL"));
    assert!(hook.contains("'/boot/EFI/BootHop/arch.efi.tmp'"));
    assert!(!hook.contains("--nopost"));
}
#[test]
fn stale_stage_is_cleared_before_initial_build_and_failure_is_terminal() {
    let mut fake = Fake::new();
    fake.files
        .insert("/boot/EFI/BootHop/arch.efi.tmp".into(), b"stale".to_vec());
    fake.modes
        .insert("/boot/EFI/BootHop/arch.efi.tmp".into(), 0o100644);
    fake.fail = Some("mkinitcpio");
    let mut backend = SystemArchSetupBackend::new(fake);
    let failure = run_arch_setup(SetupIntent::new("linux".into()), &mut backend).unwrap_err();
    assert_eq!(failure.stage, SetupStage::Build);
    assert_eq!(
        backend.calls().actions,
        ["preset", "hook", "clear", "mkinitcpio"]
    );
    assert!(
        !backend
            .calls()
            .files
            .keys()
            .any(|path| path.to_str() == Some("/boot/EFI/BootHop/arch.efi.tmp"))
    );
    assert!(!backend.calls().vars.contains_key(&key("Boot0001")));
}
#[test]
fn preexisting_matching_or_unknown_route_stops_before_preset_mutation() {
    let mut fake = Fake::new();
    fake.files.insert(
        "/usr/share/libalpm/scripts/mkinitcpio".into(),
        b"mkinitcpio --nopost".to_vec(),
    );
    let mut backend = SystemArchSetupBackend::new(fake);
    assert_eq!(
        run_arch_setup(SetupIntent::new("linux".into()), &mut backend)
            .unwrap_err()
            .stage,
        SetupStage::Plan
    );
    assert!(backend.calls().actions.is_empty());
    let mut fake = Fake::new();
    fake.files
        .insert("/boot/EFI/BootHop/arch.efi".into(), uki());
    fake.modes
        .insert("/boot/EFI/BootHop/arch.efi".into(), 0o100644);
    let mut backend = SystemArchSetupBackend::new(fake);
    assert_eq!(
        run_arch_setup(SetupIntent::new("linux".into()), &mut backend)
            .unwrap_err()
            .stage,
        SetupStage::InitialState
    );
    assert!(backend.calls().actions.is_empty());
}

#[test]
fn safety_preconditions_stop_before_configuration_or_firmware_mutation() {
    let mut cases = Vec::new();
    let mut secure = Fake::new();
    secure.vars.insert(key("SecureBoot"), (6, vec![1]));
    cases.push((secure, SetupStage::Plan));
    let mut unknown_route = Fake::new();
    unknown_route.attested = false;
    cases.push((unknown_route, SetupStage::Plan));
    let mut conflict = Fake::new();
    conflict
        .vars
        .insert(key("BootNext"), (7, 7_u16.to_le_bytes().to_vec()));
    cases.push((conflict, SetupStage::InitialState));
    let mut publisher = Fake::new();
    publisher
        .modes
        .insert("/usr/lib/boothop/boothop-uki-publish".into(), 0o100777);
    cases.push((publisher, SetupStage::Publisher));
    let mut preset = Fake::new();
    preset.files.insert(
        "/etc/mkinitcpio.d/linux.preset".into(),
        b"PRESETS=('boothop')\n".to_vec(),
    );
    cases.push((preset, SetupStage::Preset));
    for (fake, stage) in cases {
        let mut backend = SystemArchSetupBackend::new(fake);
        let failure = run_arch_setup(SetupIntent::new("linux".into()), &mut backend).unwrap_err();
        assert_eq!(failure.stage, stage);
        assert!(backend.calls().actions.is_empty());
        assert_eq!(backend.calls().vars[&key("Boot0000")].1, b"grub");
    }
}

#[test]
fn uncertain_efi_writes_report_observed_state_without_retry() {
    for fail in ["entry_after_write", "order_after_write"] {
        let mut fake = Fake::new();
        fake.fail = Some(fail);
        let mut backend = SystemArchSetupBackend::new(fake);
        let failure = run_arch_setup(SetupIntent::new("linux".into()), &mut backend).unwrap_err();
        assert_eq!(
            failure.stage,
            if fail == "entry_after_write" {
                SetupStage::Entry
            } else {
                SetupStage::Order
            }
        );
        assert_eq!(failure.observed.entry_exact, Observed::Known(Some(true)));
        assert_eq!(
            backend
                .calls()
                .actions
                .iter()
                .filter(|action| action.as_str() == "entry")
                .count(),
            1
        );
        assert_eq!(
            backend
                .calls()
                .actions
                .iter()
                .filter(|action| action.as_str() == "order")
                .count(),
            usize::from(fail == "order_after_write")
        );
        assert_eq!(backend.calls().vars[&key("Boot0000")].1, b"grub");
    }
}

#[test]
fn planning_failure_reports_uninspected_hook_and_artifact_as_unknown() {
    let mut fake = Fake::new();
    fake.vars.insert(key("SecureBoot"), (6, vec![1]));
    let mut backend = SystemArchSetupBackend::new(fake);
    let failure = run_arch_setup(SetupIntent::new("linux".into()), &mut backend).unwrap_err();
    assert_eq!(failure.stage, SetupStage::Plan);
    assert_eq!(failure.observed.preset_stanza, Observed::Unknown);
    assert_eq!(failure.observed.hook_exact, Observed::Unknown);
    assert_eq!(failure.observed.artifact_present, Observed::Unknown);
    assert!(backend.calls().actions.is_empty());
}
