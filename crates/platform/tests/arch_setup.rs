use boothop_core::{BootId, Error, GptEspIdentity};
use boothop_platform::linux::{
    arch_identity::InstalledIdentity,
    arch_setup::{
        ArchSetupBackend, ObservationError, Observed, SetupIntent, SetupProblem, SetupStage,
        run_arch_setup,
    },
    arch_uki::{
        ArchSetupSource, CmdlineSource, EspInfo, PackageHookRoute, SecureBootState, SetupError,
        UkiPlan, plan_arch_uki,
    },
    setup_firmware::{SetupFirmware, decode_boot_order},
};
use std::collections::HashMap;
#[allow(dead_code)]
mod support;
use boothop_platform::linux::store::LockedStore;
const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const PRESET: &str = "PRESETS=('default' 'fallback')\nALL_kver='/boot/vmlinuz-linux'\ndefault_image='/boot/initramfs-linux.img'\nfallback_image='/boot/initramfs-linux-fallback.img'\n";
fn name(stem: &str) -> Vec<u8> {
    format!("{stem}-{GUID}").into_bytes()
}
fn order(ids: &[u16]) -> Vec<u8> {
    ids.iter().flat_map(|id| id.to_le_bytes()).collect()
}

#[derive(Default)]
struct Firmware {
    vars: HashMap<Vec<u8>, Vec<u8>>,
    creates: usize,
    replaces: usize,
    fail: Option<&'static str>,
}
impl Firmware {
    fn new() -> Self {
        let mut value = Self::default();
        value.vars.insert(name("BootOrder"), order(&[0, 7]));
        value
            .vars
            .insert(name("Boot0000"), b"original grub".to_vec());
        value.vars.insert(name("Boot0007"), b"windows".to_vec());
        value
    }
}
impl SetupFirmware for Firmware {
    fn enumerate_variables(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.vars.keys().cloned().collect())
    }
    fn read_variable(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if self.fail == Some("entry_readback") && key == name("Boot0001") {
            return Ok(Some(b"mismatch".to_vec()));
        }
        Ok(self.vars.get(key).cloned())
    }
    fn create_boot_entry_exclusive(&mut self, id: BootId, option: &[u8]) -> Result<(), Error> {
        self.creates += 1;
        assert_eq!(id, BootId(1));
        self.vars.insert(name("Boot0001"), option.to_vec());
        if self.fail == Some("entry") {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn replace_boot_order(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.replaces += 1;
        if self.fail == Some("order") {
            return Err(Error::Busy);
        }
        self.vars.insert(name("BootOrder"), bytes.to_vec());
        if self.fail == Some("order_readback") {
            self.vars.insert(name("BootOrder"), order(&[0, 7]));
        }
        Ok(())
    }
}
struct Source;
impl ArchSetupSource for Source {
    fn installed_flavors(&self) -> Result<Vec<String>, SetupError> {
        Ok(vec!["linux".into()])
    }
    fn cmdline_source(&self) -> Result<CmdlineSource, SetupError> {
        Ok(CmdlineSource::Persistent("/etc/kernel/cmdline".into()))
    }
    fn esp_info(&self) -> Result<EspInfo, SetupError> {
        Ok(EspInfo {
            mount_point: "/boot".into(),
            filesystem: "vfat".into(),
            is_mounted: true,
            is_efi_system_partition: true,
            gpt_identity: Some(GptEspIdentity {
                partition_number: 1,
                start_lba: 2048,
                size_lba: 4096,
                guid_uefi_bytes: [1; 16],
            }),
        })
    }
    fn secure_boot_state(&self) -> Result<SecureBootState, SetupError> {
        Ok(SecureBootState::Disabled)
    }
    fn package_hook_route(&self) -> Result<Option<PackageHookRoute>, SetupError> {
        Ok(Some(PackageHookRoute {
            preset: "linux".into(),
            post_hooks_enabled: true,
        }))
    }
}
struct Fake {
    fw: Firmware,
    preset: String,
    hook: bool,
    artifact: bool,
    marker: Option<InstalledIdentity>,
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
    unknown: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            fw: Firmware::new(),
            preset: PRESET.into(),
            hook: false,
            artifact: false,
            marker: None,
            calls: vec![],
            fail: None,
            unknown: false,
        }
    }
    fn step(&mut self, name: &'static str) -> Result<(), SetupProblem> {
        self.calls.push(name);
        if self.fail == Some(name) {
            Err(SetupProblem::Backend)
        } else {
            Ok(())
        }
    }
}
impl ArchSetupBackend for Fake {
    type Firmware = Firmware;
    fn plan(&mut self, flavor: &str) -> Result<UkiPlan, SetupError> {
        self.calls.push("plan");
        plan_arch_uki(flavor, &Source)
    }
    fn firmware(&mut self) -> &mut Firmware {
        &mut self.fw
    }
    fn verify_initial_absence(&mut self, _: &UkiPlan) -> Result<(), SetupProblem> {
        self.step("initial")?;
        if self.marker.is_some() || self.artifact {
            return Err(SetupProblem::Backend);
        }
        Ok(())
    }
    fn verify_publisher(&mut self) -> Result<(), SetupProblem> {
        self.step("publisher")
    }
    fn read_preset(&mut self, _: &UkiPlan) -> Result<String, SetupProblem> {
        self.calls.push("read_preset");
        Ok(self.preset.clone())
    }
    fn write_preset_if_exact(
        &mut self,
        _: &UkiPlan,
        old: &str,
        new: &str,
    ) -> Result<(), SetupProblem> {
        assert_eq!(self.preset, old);
        self.preset = new.into();
        self.step("preset")
    }
    fn install_fixed_hook(&mut self, _: &UkiPlan) -> Result<(), SetupProblem> {
        self.hook = true;
        self.step("hook")
    }
    fn clear_stage(&mut self, _: &UkiPlan) -> Result<(), SetupProblem> {
        self.step("clear")
    }
    fn build_initial(&mut self, _: &UkiPlan) -> Result<(), SetupProblem> {
        self.step("build")?;
        self.artifact = true;
        Ok(())
    }
    fn inspect_published(&mut self, _: &UkiPlan) -> Result<(), SetupProblem> {
        self.step("artifact")
    }
    fn save_identity(&mut self, identity: &InstalledIdentity) -> Result<(), SetupProblem> {
        self.marker = Some(*identity);
        self.step("marker")
    }
    fn observe_preset_stanza(
        &mut self,
        _: Option<&UkiPlan>,
    ) -> Result<Option<String>, ObservationError> {
        if self.unknown {
            return Err(ObservationError);
        }
        Ok(self.preset.contains("'boothop'").then(|| "boothop".into()))
    }
    fn observe_hook_exact(&mut self, _: Option<&UkiPlan>) -> Result<bool, ObservationError> {
        Ok(self.hook)
    }
    fn observe_artifact(&mut self, _: Option<&UkiPlan>) -> Result<bool, ObservationError> {
        Ok(self.artifact)
    }
    fn observe_entry_exact(&mut self, id: BootId, bytes: &[u8]) -> Result<bool, ObservationError> {
        Ok(self
            .fw
            .vars
            .get(&name(&format!("Boot{:04X}", id.0)))
            .is_some_and(|v| v == bytes))
    }
    fn observe_order(&mut self) -> Result<Vec<BootId>, ObservationError> {
        decode_boot_order(
            self.fw
                .vars
                .get(&name("BootOrder"))
                .ok_or(ObservationError)?,
        )
        .map_err(|_| ObservationError)
    }
    fn observe_next(&mut self) -> Result<Option<BootId>, ObservationError> {
        if self.unknown {
            return Err(ObservationError);
        }
        Ok(self
            .fw
            .vars
            .get(&name("BootNext"))
            .map(|b| BootId(u16::from_le_bytes([b[0], b[1]]))))
    }
}

#[test]
fn succeeds_in_linear_order_and_preserves_original_order() {
    let mut fake = Fake::new();
    let result = run_arch_setup(SetupIntent::new("linux".into()), &mut fake).unwrap();
    assert_eq!(result.boot_id(), BootId(1));
    assert_eq!(fake.marker, Some(result));
    assert_eq!(fake.fw.vars[&name("BootOrder")], order(&[0, 7, 1]));
    assert_eq!(fake.fw.vars[&name("Boot0000")], b"original grub");
    assert_eq!(fake.fw.creates, 1);
    assert_eq!(fake.fw.replaces, 1);
    assert_eq!(
        fake.calls,
        [
            "plan",
            "initial",
            "publisher",
            "read_preset",
            "preset",
            "hook",
            "clear",
            "build",
            "artifact",
            "marker"
        ]
    );
    assert!(
        fake.preset
            .contains("default_image='/boot/initramfs-linux.img'")
    );
    assert!(
        fake.preset
            .contains("fallback_image='/boot/initramfs-linux-fallback.img'")
    );
}
#[test]
fn every_boundary_stops_and_reports_without_retry_or_cleanup() {
    for stage in [
        "preset",
        "hook",
        "clear",
        "build",
        "artifact",
        "entry",
        "entry_readback",
        "order",
        "order_readback",
        "marker",
    ] {
        let mut fake = Fake::new();
        if stage.starts_with("entry") || stage.starts_with("order") {
            fake.fw.fail = Some(stage);
        } else {
            fake.fail = Some(stage);
        }
        let failure = run_arch_setup(SetupIntent::new("linux".into()), &mut fake).unwrap_err();
        assert_eq!(fake.fw.vars[&name("Boot0000")], b"original grub", "{stage}");
        assert!(fake.fw.creates <= 1 && fake.fw.replaces <= 1, "{stage}");
        assert_eq!(failure.candidate_id, Some(BootId(1)), "{stage}");
        assert_eq!(
            failure.observed.hook_exact,
            Observed::Known(fake.hook),
            "{stage}"
        );
        assert_eq!(
            failure.observed.artifact_present,
            Observed::Known(fake.artifact),
            "{stage}"
        );
        if stage == "preset" {
            assert_eq!(failure.stage, SetupStage::Preset);
        }
        if stage == "hook" {
            assert_eq!(failure.stage, SetupStage::Hook);
        }
        if stage == "order" {
            assert_eq!(failure.stage, SetupStage::Order);
        }
        if stage == "marker" {
            assert_eq!(failure.stage, SetupStage::Marker);
        }
    }
}
#[test]
fn failure_inspection_marks_unreadable_states_unknown() {
    let mut fake = Fake::new();
    fake.fail = Some("hook");
    fake.unknown = true;
    let failure = run_arch_setup(SetupIntent::new("linux".into()), &mut fake).unwrap_err();
    assert_eq!(failure.observed.preset_stanza, Observed::Unknown);
    assert_eq!(failure.observed.boot_next, Observed::Unknown);
}
#[test]
fn preexisting_artifact_stops_before_preset_mutation() {
    let mut fake = Fake::new();
    fake.artifact = true;
    let failure = run_arch_setup(SetupIntent::new("linux".into()), &mut fake).unwrap_err();
    assert_eq!(failure.stage, SetupStage::InitialState);
    assert_eq!(fake.preset, PRESET);
    assert_eq!(fake.fw.creates, 0);
}

#[test]
fn marker_save_is_atomic_and_refuses_replacement() {
    let fs = support::FakeFs::installed();
    let identity = InstalledIdentity::new(BootId(1), [0x12; 32]).unwrap();
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    store.save_arch_identity(&identity).unwrap();
    let saved = fs.0.borrow().nodes["/var/lib/boothop/arch-direct.identity"]
        .borrow()
        .bytes
        .clone();
    assert_eq!(saved, identity.encode());
    assert_eq!(store.save_arch_identity(&identity), Err(Error::Busy));
    assert_eq!(
        fs.0.borrow().nodes["/var/lib/boothop/arch-direct.identity"]
            .borrow()
            .bytes,
        saved
    );
    drop(store);
    assert!(!fs.held());
}

#[test]
fn marker_sync_failure_is_unknown_and_never_retried() {
    let fs = support::FakeFs::installed();
    fs.0.borrow_mut().fail = Some(("dir_fsync", 5));
    let identity = InstalledIdentity::new(BootId(1), [0x12; 32]).unwrap();
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(
        store.save_arch_identity(&identity),
        Err(Error::StoreDurabilityUnknown { raw_code: 5 })
    );
    assert_eq!(
        fs.0.borrow()
            .events
            .iter()
            .filter(|event| event.as_str() == "rename")
            .count(),
        1
    );
}
