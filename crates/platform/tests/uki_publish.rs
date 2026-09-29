use boothop_platform::linux::uki::{
    UkiBuildBackend, UkiBuildError, UkiBuildPlan, UkiPolicy, UkiPublishFs, build_and_publish_uki,
    discover_uki_plan,
};
use std::collections::BTreeMap;

#[derive(Default)]
struct FixtureFs {
    files: BTreeMap<String, String>,
}

impl FixtureFs {
    fn ready() -> Self {
        let mut fs = Self::default();
        fs.files.insert(
            "/etc/mkinitcpio.d/linux.preset".into(),
            "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\ndefault_cmdline='/etc/boothop/cmdline'\n".into(),
        );
        fs.files
            .insert("/etc/boothop/cmdline".into(), "root=UUID=abc rw".into());
        fs.files.insert(
            "/etc/mkinitcpio.conf".into(),
            "HOOKS=(base udev autodetect microcode modconf block filesystems)\n".into(),
        );
        fs.files
            .insert("/boot/vmlinuz-linux".into(), "kernel".into());
        fs.files
            .insert("/boot/initramfs-linux.img".into(), "initramfs".into());
        fs
    }
}

impl boothop_platform::linux::uki::ArchConfigFs for FixtureFs {
    fn read_text(&self, path: &str) -> Result<Option<String>, String> {
        Ok(self.files.get(path).cloned())
    }
    fn is_file(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }
    fn is_directory(&self, path: &str) -> bool {
        matches!(path, "/boot" | "/boot/EFI" | "/boot/EFI/BootHop")
    }
    fn is_mounted_esp(&self, mount_path: &str) -> bool {
        mount_path == "/boot"
    }
}

fn plan() -> UkiBuildPlan {
    discover_uki_plan(
        &FixtureFs::ready(),
        &UkiPolicy {
            selected_flavor: Some("linux".into()),
            esp_mount: "/boot".into(),
            secure_boot_required: false,
            signer_configured: false,
        },
    )
    .unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailAt {
    None,
    Build,
    Validate,
    Sign,
    StageWrite,
    DiskFull,
    Rename,
}

struct FakeBuilder(FailAt);
impl UkiBuildBackend for FakeBuilder {
    fn build(&mut self, _: &UkiBuildPlan) -> Result<Vec<u8>, UkiBuildError> {
        if self.0 == FailAt::Build {
            Err(UkiBuildError::Build("fake mkinitcpio failure".into()))
        } else {
            Ok(b"new verified UKI".to_vec())
        }
    }
    fn validate(&mut self, _: &[u8], _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        if self.0 == FailAt::Validate {
            Err(UkiBuildError::Validation("invalid PE image".into()))
        } else {
            Ok(())
        }
    }
    fn sign_if_required(&mut self, _: &mut Vec<u8>, _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        if self.0 == FailAt::Sign {
            Err(UkiBuildError::Signing("signer failed".into()))
        } else {
            Ok(())
        }
    }
}

struct FakePublishFs {
    files: BTreeMap<String, Vec<u8>>,
    fail_at: FailAt,
}
impl UkiPublishFs for FakePublishFs {
    fn write_stage(&mut self, path: &str, contents: &[u8]) -> Result<(), UkiBuildError> {
        if self.fail_at == FailAt::StageWrite {
            self.files.insert(path.into(), contents[..5].to_vec());
            return Err(UkiBuildError::Publish("incomplete stage".into()));
        }
        if self.fail_at == FailAt::DiskFull {
            self.files.insert(path.into(), contents[..5].to_vec());
            return Err(UkiBuildError::DiskFull);
        }
        self.files.insert(path.into(), contents.to_vec());
        Ok(())
    }
    fn rename_stage_over_final(
        &mut self,
        stage_path: &str,
        final_path: &str,
    ) -> Result<(), UkiBuildError> {
        if self.fail_at == FailAt::Rename {
            return Err(UkiBuildError::Publish("atomic rename failed".into()));
        }
        let staged = self
            .files
            .remove(stage_path)
            .ok_or_else(|| UkiBuildError::Publish("missing complete stage".into()))?;
        self.files.insert(final_path.into(), staged);
        Ok(())
    }
}

fn run(fail_at: FailAt) -> FakePublishFs {
    let mut plan = plan();
    if fail_at == FailAt::Sign {
        plan.secure_boot.signing_required = true;
        plan.secure_boot.signer_already_configured = true;
        plan.validation.verify_after_signing = true;
    }
    let mut builder = FakeBuilder(fail_at);
    let mut fs = FakePublishFs {
        files: BTreeMap::from([("EFI/BootHop/arch.efi".into(), b"previous UKI".to_vec())]),
        fail_at,
    };
    let _ = build_and_publish_uki(&plan, &mut builder, &mut fs);
    fs
}

#[test]
fn every_build_validation_signing_and_stage_failure_keeps_previous_stable_uki() {
    for fail_at in [
        FailAt::Build,
        FailAt::Validate,
        FailAt::Sign,
        FailAt::StageWrite,
        FailAt::DiskFull,
    ] {
        let fs = run(fail_at);
        assert_eq!(
            fs.files.get("EFI/BootHop/arch.efi").unwrap(),
            b"previous UKI",
            "{fail_at:?}"
        );
    }
}

#[test]
fn successful_publication_uses_fixed_final_path_and_atomic_replace() {
    let fs = run(FailAt::None);
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"new verified UKI"
    );
    assert!(!fs.files.contains_key("EFI/BootHop/arch.efi.staging"));
    assert_eq!(fs.files.len(), 1);
}

#[test]
fn failed_atomic_rename_keeps_previous_stable_uki_and_staging_is_separate() {
    let fs = run(FailAt::Rename);
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"previous UKI"
    );
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi.staging").unwrap(),
        b"new verified UKI"
    );
}
