#![cfg(target_os = "linux")]

use boothop_core::{
    ArchProvisionState, ProvisioningRecord, ProvisioningStep, PublishMetadata, Residual,
    UninstallingRecord, UninstallingStep,
};
use boothop_platform::linux::uki::{
    UkiBuildBackend, UkiBuildError, UkiBuildPlan, UkiConfigSnapshot, UkiFinalPathState, UkiPolicy,
    UkiPublicationAuthority, UkiPublishFs, UkiPublishJournal, build_and_publish_uki,
    plan_uki_snapshot, verify_interrupted_initial_publication,
};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

#[allow(dead_code)]
mod support;

#[derive(Default)]
struct FixtureConfig {
    files: BTreeMap<String, String>,
}

impl FixtureConfig {
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

    fn snapshot(&self) -> UkiConfigSnapshot {
        UkiConfigSnapshot {
            mounted_esp: Some("/boot".into()),
            esp_efi_directory: true,
            esp_boothop_directory: true,
            regular_files: self.files.keys().cloned().collect::<BTreeSet<_>>(),
            text_files: self.files.clone(),
            directory_entries: BTreeMap::new(),
        }
    }
}

fn plan() -> UkiBuildPlan {
    let fixture = FixtureConfig::ready();
    plan_uki_snapshot(
        &fixture.snapshot(),
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
    AfterRename,
    ReadbackMismatch,
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
    events: Rc<RefCell<Vec<&'static str>>>,
}
impl UkiPublishFs for FakePublishFs {
    fn final_path_state(&mut self, path: &str) -> Result<UkiFinalPathState, UkiBuildError> {
        self.events.borrow_mut().push("read-final");
        Ok(match self.files.get(path) {
            Some(contents) => UkiFinalPathState::Regular(PublishMetadata {
                sha256: Sha256::digest(contents).into(),
                size: contents.len() as u64,
            }),
            None => UkiFinalPathState::Absent,
        })
    }

    fn write_stage(&mut self, path: &str, contents: &[u8]) -> Result<(), UkiBuildError> {
        self.events.borrow_mut().push("stage");
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
        self.events.borrow_mut().push("rename");
        verify_fake_authority(self, final_path, authority)?;
        let staged = self
            .files
            .remove(stage_path)
            .ok_or_else(|| UkiBuildError::Publish("missing complete stage".into()))?;
        self.files.insert(final_path.into(), staged);
        if self.fail_at == FailAt::ReadbackMismatch {
            self.files
                .insert(final_path.into(), b"corrupted after rename".to_vec());
        }
        if self.fail_at == FailAt::AfterRename {
            return Err(UkiBuildError::Publish(
                "simulated interruption after rename".into(),
            ));
        }
        Ok(())
    }
}

struct FakeJournal {
    state: ArchProvisionState,
    fail_attempt_save: bool,
    fail_save: bool,
    events: Rc<RefCell<Vec<&'static str>>>,
}

impl UkiPublishJournal for FakeJournal {
    fn persist_initial_publication_attempt(
        &mut self,
        metadata: &PublishMetadata,
    ) -> Result<(), UkiBuildError> {
        if self.fail_attempt_save {
            return Err(UkiBuildError::Publish("attempt journal save failed".into()));
        }
        self.events.borrow_mut().push("attempted");
        let ArchProvisionState::Provisioning(record) = &mut self.state else {
            return Err(UkiBuildError::Publish("not provisioning".into()));
        };
        if record.step != ProvisioningStep::UkiPublicationPending {
            return Err(UkiBuildError::Publish("not publication pending".into()));
        }
        record.owned_entry.publish = Some(metadata.clone());
        record.step = ProvisioningStep::UkiPublicationAttempted;
        Ok(())
    }

    fn mark_initial_uki_published(
        &mut self,
        metadata: &PublishMetadata,
    ) -> Result<(), UkiBuildError> {
        self.events.borrow_mut().push("published");
        if self.fail_save {
            return Err(UkiBuildError::Publish("journal save failed".into()));
        }
        let ArchProvisionState::Provisioning(record) = &mut self.state else {
            return Err(UkiBuildError::Publish("not provisioning".into()));
        };
        if record.step != ProvisioningStep::UkiPublicationAttempted
            || record.owned_entry.publish.as_ref() != Some(metadata)
        {
            return Err(UkiBuildError::Publish("attempt metadata mismatch".into()));
        }
        record.step = ProvisioningStep::UkiPublished;
        Ok(())
    }

    fn persist_ready_uki_update(
        &mut self,
        metadata: &PublishMetadata,
    ) -> Result<(), UkiBuildError> {
        self.events.borrow_mut().push("ready-update");
        if self.fail_save {
            return Err(UkiBuildError::Publish("journal save failed".into()));
        }
        let ArchProvisionState::Ready(entry) = &mut self.state else {
            return Err(UkiBuildError::Publish("not ready".into()));
        };
        entry.publish = Some(metadata.clone());
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
        (UkiPublicationAuthority::ProvisioningAttempted(_), UkiFinalPathState::Absent) => Ok(()),
        (UkiPublicationAuthority::Ready(expected), UkiFinalPathState::Regular(actual))
            if expected == &actual =>
        {
            Ok(())
        }
        _ => Err(UkiBuildError::Publish("ownership metadata mismatch".into())),
    }
}

fn provisioning_state() -> ArchProvisionState {
    let ArchProvisionState::Ready(mut owned_entry) = support::ready_state() else {
        unreachable!()
    };
    owned_entry.publish = None;
    ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: "op-1".into(),
        operation_version: 1,
        owned_entry,
        step: ProvisioningStep::UkiPublicationPending,
        residual: Vec::<Residual>::new(),
    })
}

fn fake_publish_fs(
    files: BTreeMap<String, Vec<u8>>,
    fail_at: FailAt,
    events: Rc<RefCell<Vec<&'static str>>>,
) -> FakePublishFs {
    FakePublishFs {
        files,
        fail_at,
        events,
    }
}

fn fake_journal(state: ArchProvisionState, events: Rc<RefCell<Vec<&'static str>>>) -> FakeJournal {
    FakeJournal {
        state,
        fail_attempt_save: false,
        fail_save: false,
        events,
    }
}

fn ready_state_for(contents: &[u8]) -> ArchProvisionState {
    let ArchProvisionState::Ready(mut entry) = support::ready_state() else {
        unreachable!()
    };
    entry.publish = Some(PublishMetadata {
        sha256: Sha256::digest(contents).into(),
        size: contents.len() as u64,
    });
    ArchProvisionState::Ready(entry)
}

fn run_fake_publication(fail_at: FailAt) -> FakePublishFs {
    let mut plan = plan();
    if fail_at == FailAt::Sign {
        plan.secure_boot.signing_required = true;
        plan.secure_boot.signer_already_configured = true;
        plan.validation.verify_after_signing = true;
    }
    let stable = b"previous UKI";
    let state = ready_state_for(stable);
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut journal = fake_journal(state.clone(), events.clone());
    let mut builder = FakeBuilder::new(fail_at);
    let mut fs = fake_publish_fs(
        BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
        fail_at,
        events,
    );
    let _ = build_and_publish_uki(&plan, &state, &mut journal, &mut builder, &mut fs);
    fs
}

#[test]
fn provisioning_authority_publishes_only_to_an_absent_final_path() {
    let plan = plan();
    let mut builder = FakeBuilder::new(FailAt::None);
    let state = provisioning_state();
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut journal = fake_journal(state.clone(), events.clone());
    let mut absent = fake_publish_fs(BTreeMap::new(), FailAt::None, events.clone());
    let metadata =
        build_and_publish_uki(&plan, &state, &mut journal, &mut builder, &mut absent).unwrap();
    assert_eq!(
        absent.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"new verified UKI"
    );
    let expected_sha256: [u8; 32] = Sha256::digest(b"new verified UKI").into();
    assert_eq!(metadata.sha256, expected_sha256);
    assert_eq!(metadata.size, b"new verified UKI".len() as u64);
    assert!(matches!(
        journal.state,
        ArchProvisionState::Provisioning(ProvisioningRecord {
            step: ProvisioningStep::UkiPublished,
            ..
        })
    ));
    let ArchProvisionState::Provisioning(published_record) = &journal.state else {
        unreachable!()
    };
    assert_eq!(published_record.owned_entry.publish, Some(metadata));
    let event_log = events.borrow();
    let attempted = event_log
        .iter()
        .position(|event| *event == "attempted")
        .unwrap();
    let stage = event_log
        .iter()
        .position(|event| *event == "stage")
        .unwrap();
    let rename = event_log
        .iter()
        .position(|event| *event == "rename")
        .unwrap();
    let readback = event_log
        .iter()
        .rposition(|event| *event == "read-final")
        .unwrap();
    let published = event_log
        .iter()
        .position(|event| *event == "published")
        .unwrap();
    assert!(attempted < stage && stage < rename && rename < readback && readback < published);

    let stable = b"unowned existing UKI";
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut unowned = fake_publish_fs(
        BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
        FailAt::None,
        events.clone(),
    );
    let mut blocked_builder = FakeBuilder::new(FailAt::None);
    let mut blocked_journal = fake_journal(provisioning_state(), events);
    let error = build_and_publish_uki(
        &plan,
        &blocked_journal.state.clone(),
        &mut blocked_journal,
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
    let state = ready_state_for(stable);
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut journal = fake_journal(state.clone(), events.clone());
    let mut exact = fake_publish_fs(
        BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
        FailAt::None,
        events.clone(),
    );
    build_and_publish_uki(
        &plan,
        &state,
        &mut journal,
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
        state.publish = Some(expected);
        let state = ArchProvisionState::Ready(state);
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut journal = fake_journal(state.clone(), events.clone());
        let mut mismatch = fake_publish_fs(
            BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
            FailAt::None,
            events,
        );
        let mut builder = FakeBuilder::new(FailAt::None);
        let error = build_and_publish_uki(&plan, &state, &mut journal, &mut builder, &mut mismatch)
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
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut journal = fake_journal(state.clone(), events.clone());
        let mut fs = fake_publish_fs(BTreeMap::new(), FailAt::None, events);
        let mut builder = FakeBuilder::new(FailAt::None);
        assert!(build_and_publish_uki(&plan, &state, &mut journal, &mut builder, &mut fs).is_err());
        assert_eq!(builder.build_calls, 0);
        assert!(fs.files.is_empty());
    }
}

#[test]
fn residual_pending_checkpoint_cannot_restart_publication() {
    let plan = plan();
    let mut state = provisioning_state();
    if let ArchProvisionState::Provisioning(record) = &mut state {
        record.residual.push(Residual::UkiMayRemain);
    }
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut journal = fake_journal(state.clone(), events.clone());
    let mut fs = fake_publish_fs(BTreeMap::new(), FailAt::None, events);
    let mut builder = FakeBuilder::new(FailAt::None);

    assert!(build_and_publish_uki(&plan, &state, &mut journal, &mut builder, &mut fs).is_err());
    assert_eq!(builder.build_calls, 0);
    assert!(fs.files.is_empty());
}

#[test]
fn interrupted_initial_publication_is_reconciliation_only() {
    let plan = plan();
    let pending = provisioning_state();
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut journal = fake_journal(pending.clone(), events.clone());
    let mut fs = fake_publish_fs(BTreeMap::new(), FailAt::AfterRename, events);
    let mut builder = FakeBuilder::new(FailAt::None);
    assert!(build_and_publish_uki(&plan, &pending, &mut journal, &mut builder, &mut fs).is_err());
    assert_eq!(builder.build_calls, 1);

    let ArchProvisionState::Provisioning(record) = &journal.state else {
        unreachable!()
    };
    assert_eq!(record.step, ProvisioningStep::UkiPublicationAttempted);
    let attempted_metadata = record.owned_entry.publish.as_ref().unwrap().clone();
    assert_eq!(
        verify_interrupted_initial_publication(&journal.state, &mut fs).unwrap(),
        attempted_metadata
    );
    assert_eq!(record.step, ProvisioningStep::UkiPublicationAttempted);

    let mut absent = fake_publish_fs(BTreeMap::new(), FailAt::None, Rc::new(RefCell::new(vec![])));
    assert!(verify_interrupted_initial_publication(&journal.state, &mut absent).is_err());
    let mut mismatched = fake_publish_fs(
        BTreeMap::from([("EFI/BootHop/arch.efi".into(), b"wrong output".to_vec())]),
        FailAt::None,
        Rc::new(RefCell::new(vec![])),
    );
    assert!(verify_interrupted_initial_publication(&journal.state, &mut mismatched).is_err());

    let mut retry_journal = fake_journal(journal.state.clone(), Rc::new(RefCell::new(vec![])));
    let mut retry_builder = FakeBuilder::new(FailAt::None);
    assert!(
        build_and_publish_uki(
            &plan,
            &retry_journal.state.clone(),
            &mut retry_journal,
            &mut retry_builder,
            &mut fs
        )
        .is_err()
    );
    assert_eq!(retry_builder.build_calls, 0);
}

#[test]
fn initial_readback_or_completion_save_failure_never_claims_published() {
    let plan = plan();
    let pending = provisioning_state();

    let events = Rc::new(RefCell::new(Vec::new()));
    let mut mismatch_journal = fake_journal(pending.clone(), events.clone());
    let mut mismatch_fs = fake_publish_fs(BTreeMap::new(), FailAt::ReadbackMismatch, events);
    let mut builder = FakeBuilder::new(FailAt::None);
    assert!(
        build_and_publish_uki(
            &plan,
            &pending,
            &mut mismatch_journal,
            &mut builder,
            &mut mismatch_fs
        )
        .is_err()
    );
    let ArchProvisionState::Provisioning(record) = &mismatch_journal.state else {
        unreachable!()
    };
    assert_eq!(record.step, ProvisioningStep::UkiPublicationAttempted);
    assert!(
        verify_interrupted_initial_publication(&mismatch_journal.state, &mut mismatch_fs).is_err()
    );
    assert_eq!(builder.build_calls, 1);

    let events = Rc::new(RefCell::new(Vec::new()));
    let mut failed_save_journal = fake_journal(pending.clone(), events.clone());
    failed_save_journal.fail_save = true;
    let mut failed_save_fs = fake_publish_fs(BTreeMap::new(), FailAt::None, events);
    assert!(
        build_and_publish_uki(
            &plan,
            &pending,
            &mut failed_save_journal,
            &mut FakeBuilder::new(FailAt::None),
            &mut failed_save_fs
        )
        .is_err()
    );
    let ArchProvisionState::Provisioning(record) = &failed_save_journal.state else {
        unreachable!()
    };
    assert_eq!(record.step, ProvisioningStep::UkiPublicationAttempted);
    assert!(
        verify_interrupted_initial_publication(&failed_save_journal.state, &mut failed_save_fs)
            .is_ok()
    );
}

#[test]
fn initial_attempt_is_durable_before_staging_write() {
    let plan = plan();
    let pending = provisioning_state();
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut journal = fake_journal(pending.clone(), events.clone());
    let mut fs = fake_publish_fs(BTreeMap::new(), FailAt::StageWrite, events.clone());
    assert!(
        build_and_publish_uki(
            &plan,
            &pending,
            &mut journal,
            &mut FakeBuilder::new(FailAt::None),
            &mut fs
        )
        .is_err()
    );

    let ArchProvisionState::Provisioning(record) = &journal.state else {
        unreachable!()
    };
    assert_eq!(record.step, ProvisioningStep::UkiPublicationAttempted);
    assert!(record.owned_entry.publish.is_some());
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi.staging").unwrap(),
        b"new v"
    );
    assert!(!fs.files.contains_key("EFI/BootHop/arch.efi"));
    let event_log = events.borrow();
    let attempted = event_log
        .iter()
        .position(|event| *event == "attempted")
        .unwrap();
    let stage = event_log
        .iter()
        .position(|event| *event == "stage")
        .unwrap();
    assert!(attempted < stage);
}

#[test]
fn failed_attempt_checkpoint_does_not_write_to_the_esp() {
    let plan = plan();
    let pending = provisioning_state();
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut journal = fake_journal(pending.clone(), events.clone());
    journal.fail_attempt_save = true;
    let mut fs = fake_publish_fs(BTreeMap::new(), FailAt::None, events.clone());
    assert!(
        build_and_publish_uki(
            &plan,
            &pending,
            &mut journal,
            &mut FakeBuilder::new(FailAt::None),
            &mut fs
        )
        .is_err()
    );
    assert_eq!(journal.state, pending);
    assert!(fs.files.is_empty());
    let event_log = events.borrow();
    assert!(!event_log.contains(&"stage"));
    assert!(!event_log.contains(&"rename"));
}

#[test]
fn ready_update_journal_save_failure_blocks_the_next_update() {
    let plan = plan();
    let stable = b"old ready UKI";
    let state = ready_state_for(stable);
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut journal = fake_journal(state.clone(), events.clone());
    journal.fail_save = true;
    let mut fs = fake_publish_fs(
        BTreeMap::from([("EFI/BootHop/arch.efi".into(), stable.to_vec())]),
        FailAt::None,
        events,
    );
    assert!(
        build_and_publish_uki(
            &plan,
            &state,
            &mut journal,
            &mut FakeBuilder::new(FailAt::None),
            &mut fs
        )
        .is_err()
    );
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"new verified UKI"
    );
    assert_eq!(journal.state, state);

    let old_journal_state = journal.state.clone();
    journal.fail_save = false;
    let mut builder = FakeBuilder::new(FailAt::None);
    assert!(
        build_and_publish_uki(
            &plan,
            &old_journal_state,
            &mut journal,
            &mut builder,
            &mut fs
        )
        .is_err()
    );
    assert_eq!(builder.build_calls, 0);
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"new verified UKI"
    );
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
        let fs = run_fake_publication(fail_at);
        assert_eq!(
            fs.files.get("EFI/BootHop/arch.efi").unwrap(),
            b"previous UKI",
            "{fail_at:?}"
        );
    }
}

#[test]
fn successful_publication_uses_fixed_final_path_and_atomic_replace() {
    let fs = run_fake_publication(FailAt::None);
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"new verified UKI"
    );
    assert!(!fs.files.contains_key("EFI/BootHop/arch.efi.staging"));
    assert_eq!(fs.files.len(), 1);
}

#[test]
fn failed_atomic_rename_keeps_previous_stable_uki_and_staging_is_separate() {
    let fs = run_fake_publication(FailAt::Rename);
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi").unwrap(),
        b"previous UKI"
    );
    assert_eq!(
        fs.files.get("EFI/BootHop/arch.efi.staging").unwrap(),
        b"new verified UKI"
    );
}
