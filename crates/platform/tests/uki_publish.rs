use boothop_core::{
    ArchProvisionState, ProvisioningRecord, ProvisioningStep, PublishMetadata, Residual,
    UninstallingRecord, UninstallingStep,
};
use boothop_platform::linux::uki::{
    UkiBuildBackend, UkiBuildError, UkiBuildPlan, UkiFinalPathState, UkiPolicy,
    UkiPublicationAuthority, UkiPublishFs, build_and_publish_uki, discover_uki_plan,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[allow(dead_code)]
mod support;

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
    fn files_in_directory(&self, _: &str) -> Result<Vec<String>, String> {
        Ok(Vec::new())
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

struct FakeBuilder {
    fail_at: FailAt,
    build_calls: usize,
}

impl FakeBuilder {
    fn new(fail_at: FailAt) -> Self {
        Self {
            fail_at,
            build_calls: 0,
        }
    }
}

impl UkiBuildBackend for FakeBuilder {
    fn build(&mut self, _: &UkiBuildPlan) -> Result<Vec<u8>, UkiBuildError> {
        self.build_calls += 1;
        if self.fail_at == FailAt::Build {
            Err(UkiBuildError::Build("fake mkinitcpio failure".into()))
        } else {
            Ok(b"new verified UKI".to_vec())
        }
    }
    fn validate(&mut self, _: &[u8], _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        if self.fail_at == FailAt::Validate {
            Err(UkiBuildError::Validation("invalid PE image".into()))
        } else {
            Ok(())
        }
    }
    fn sign_if_required(&mut self, _: &mut Vec<u8>, _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        if self.fail_at == FailAt::Sign {
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
    fn final_path_state(&mut self, path: &str) -> Result<UkiFinalPathState, UkiBuildError> {
        Ok(match self.files.get(path) {
            Some(contents) => UkiFinalPathState::Regular(PublishMetadata {
                sha256: Sha256::digest(contents).into(),
                size: contents.len() as u64,
            }),
            None => UkiFinalPathState::Absent,
        })
    }

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
        authority: &UkiPublicationAuthority,
    ) -> Result<(), UkiBuildError> {
        if self.fail_at == FailAt::Rename {
            return Err(UkiBuildError::Publish("atomic rename failed".into()));
        }
        verify_fake_authority(self, final_path, authority)?;
        let staged = self
            .files
            .remove(stage_path)
            .ok_or_else(|| UkiBuildError::Publish("missing complete stage".into()))?;
        self.files.insert(final_path.into(), staged);
        Ok(())
    }
}

fn verify_fake_authority(
    fs: &mut FakePublishFs,
    path: &str,
    authority: &UkiPublicationAuthority,
) -> Result<(), UkiBuildError> {
    let state = fs.final_path_state(path)?;
    match (authority, state) {
        (UkiPublicationAuthority::Provisioning, UkiFinalPathState::Absent) => Ok(()),
        (UkiPublicationAuthority::Ready(expected), UkiFinalPathState::Regular(actual))
            if expected == &actual =>
        {
            Ok(())
        }
        _ => Err(UkiBuildError::Publish("ownership metadata mismatch".into())),
    }
}

fn provisioning_state() -> ArchProvisionState {
    let ArchProvisionState::Ready(owned_entry) = support::ready_state() else {
        unreachable!()
    };
    ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: "op-1".into(),
        operation_version: 1,
        owned_entry,
        step: ProvisioningStep::UkiPublished,
        residual: Vec::<Residual>::new(),
    })
}

fn ready_state_for(contents: &[u8]) -> ArchProvisionState {
    let ArchProvisionState::Ready(mut entry) = support::ready_state() else {
        unreachable!()
    };
    entry.publish = PublishMetadata {
        sha256: Sha256::digest(contents).into(),
        size: contents.len() as u64,
    };
    ArchProvisionState::Ready(entry)
}

fn run(fail_at: FailAt) -> FakePublishFs {
    let mut plan = plan();
    if fail_at == FailAt::Sign {
        plan.secure_boot.signing_required = true;
        plan.secure_boot.signer_already_configured = true;
        plan.validation.verify_after_signing = true;
    }
    let mut builder = FakeBuilder::new(fail_at);
    let stable = b"previous UKI";
    let mut fs = FakePublishFs {
        files: BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
        fail_at,
    };
    let _ = build_and_publish_uki(&plan, &ready_state_for(stable), &mut builder, &mut fs);
    fs
}

#[test]
fn provisioning_authority_publishes_only_to_an_absent_final_path() {
    let plan = plan();
    let mut builder = FakeBuilder::new(FailAt::None);
    let mut absent = FakePublishFs {
        files: BTreeMap::new(),
        fail_at: FailAt::None,
    };
    let metadata =
        build_and_publish_uki(&plan, &provisioning_state(), &mut builder, &mut absent).unwrap();
    assert_eq!(
        absent.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"new verified UKI"
    );
    let expected_sha256: [u8; 32] = Sha256::digest(b"new verified UKI").into();
    assert_eq!(metadata.sha256, expected_sha256);
    assert_eq!(metadata.size, b"new verified UKI".len() as u64);

    let stable = b"unowned existing UKI";
    let mut unowned = FakePublishFs {
        files: BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
        fail_at: FailAt::None,
    };
    let mut blocked_builder = FakeBuilder::new(FailAt::None);
    let error = build_and_publish_uki(
        &plan,
        &provisioning_state(),
        &mut blocked_builder,
        &mut unowned,
    )
    .unwrap_err();
    assert!(error.to_string().contains("absent stable UKI"));
    assert_eq!(blocked_builder.build_calls, 0);
    assert_eq!(unowned.files.get("EFI/BootHop/arch.efi").unwrap(), stable);
}

#[test]
fn ready_update_requires_exact_journaled_hash_and_size_before_build() {
    let plan = plan();
    let stable = b"owned previous UKI";
    let mut exact = FakePublishFs {
        files: BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
        fail_at: FailAt::None,
    };
    build_and_publish_uki(
        &plan,
        &ready_state_for(stable),
        &mut FakeBuilder::new(FailAt::None),
        &mut exact,
    )
    .unwrap();
    assert_eq!(
        exact.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"new verified UKI"
    );

    for expected in [
        PublishMetadata {
            sha256: [0x55; 32],
            size: stable.len() as u64,
        },
        PublishMetadata {
            sha256: Sha256::digest(stable).into(),
            size: stable.len() as u64 + 1,
        },
    ] {
        let ArchProvisionState::Ready(mut state) = ready_state_for(stable) else {
            unreachable!()
        };
        state.publish = expected;
        let mut mismatch = FakePublishFs {
            files: BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
            fail_at: FailAt::None,
        };
        let mut builder = FakeBuilder::new(FailAt::None);
        let error = build_and_publish_uki(
            &plan,
            &ArchProvisionState::Ready(state),
            &mut builder,
            &mut mismatch,
        )
        .unwrap_err();
        assert!(error.to_string().contains("journaled ownership"));
        assert_eq!(builder.build_calls, 0);
        assert_eq!(mismatch.files.get("EFI/BootHop/arch.efi").unwrap(), stable);
        assert!(!mismatch.files.contains_key("EFI/BootHop/arch.efi.staging"));
    }
}

#[test]
fn missing_or_unknown_journal_state_fails_closed() {
    let plan = plan();
    let ArchProvisionState::Provisioning(provisioning) = provisioning_state() else {
        unreachable!()
    };
    let states = [
        ArchProvisionState::Unprovisioned,
        ArchProvisionState::Uninstalling(UninstallingRecord {
            operation_id: provisioning.operation_id,
            operation_version: provisioning.operation_version,
            owned_entry: provisioning.owned_entry,
            step: UninstallingStep::Started,
            residual: Vec::new(),
        }),
    ];
    for state in states {
        let mut fs = FakePublishFs {
            files: BTreeMap::new(),
            fail_at: FailAt::None,
        };
        let mut builder = FakeBuilder::new(FailAt::None);
        assert!(build_and_publish_uki(&plan, &state, &mut builder, &mut fs).is_err());
        assert_eq!(builder.build_calls, 0);
        assert!(fs.files.is_empty());
    }
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
