#![cfg(target_os = "linux")]
mod support;

use boothop_core::{
    ArchProvisionState, BootOrderRemovalProof, BootOrderSnapshot, Error, PlatformOperation,
    ProvisioningRecord, ProvisioningStep, Residual, UninstalledRecord, UninstallingStep,
};
use boothop_platform::linux::{
    arch_provision_store::ArchProvisionStore, boot_order::begin_uninstall,
};
use support::*;

#[test]
fn missing_journal_is_unprovisioned_and_ready_state_is_saved_separately() {
    let fs = FakeFs::installed();
    fs.set_record(boothop_core::encode_record(&target()).unwrap());
    let ordinary_record = fs.record();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Ok(ArchProvisionState::Unprovisioned));
    let pending = pending_state();
    store.save(&pending).unwrap();
    assert_eq!(store.load(), Ok(pending.clone()));

    let publish = match ready_state() {
        ArchProvisionState::Ready(entry) => entry.publish.unwrap(),
        _ => unreachable!(),
    };
    let mut forged_attempt = pending.clone();
    if let ArchProvisionState::Provisioning(record) = &mut forged_attempt {
        record.step = ProvisioningStep::UkiPublicationAttempted;
        record.owned_entry.publish = Some(publish);
    }
    let old = fs.journal();
    assert_eq!(store.save(&forged_attempt), Err(Error::NotConfigured));
    assert_eq!(fs.journal(), old);
    assert_eq!(store.load(), Ok(pending));

    assert_eq!(fs.record(), ordinary_record);
}

#[test]
fn ready_allows_uninstall_intent_but_not_unverified_progress_or_metadata_changes() {
    let fs = FakeFs::installed();
    let ArchProvisionState::Ready(entry) = ready_state() else {
        unreachable!()
    };
    fs.set_journal(
        boothop_core::encode_arch_provision_state(&ArchProvisionState::Ready(entry.clone()))
            .unwrap(),
    );
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Ok(ArchProvisionState::Ready(entry.clone())));

    let mut forged_update = entry.clone();
    forged_update.build.kernel_release = "6.12.2-zen1-1-zen".into();
    forged_update.build.initramfs_sha256 = [0x33; 32];
    forged_update.publish = Some(boothop_core::PublishMetadata {
        sha256: [0x44; 32],
        size: 43,
    });
    let forged_update = ArchProvisionState::Ready(forged_update);
    let old = fs.journal();
    assert_eq!(store.save(&forged_update), Err(Error::NotConfigured));
    assert_eq!(fs.journal(), old);

    let mut changed_identity = entry.clone();
    changed_identity.boot_id = boothop_core::BootId(changed_identity.boot_id.0.wrapping_add(1));
    let changed_identity = ArchProvisionState::Ready(changed_identity);
    let old = fs.journal();
    assert_eq!(store.save(&changed_identity), Err(Error::NotConfigured));
    assert_eq!(fs.journal(), old);

    let mut state = begin_uninstall(entry, "test-uninstall".into()).unwrap();
    store.save(&state).unwrap();
    if let ArchProvisionState::Uninstalling(record) = &mut state {
        record.step = UninstallingStep::BootOrderRemovalAttempted;
    }
    let old = fs.journal();
    assert_eq!(store.save(&state), Err(Error::NotConfigured));
    assert_eq!(fs.journal(), old);
    if let ArchProvisionState::Uninstalling(record) = &mut state {
        record.step = UninstallingStep::Started;
    }
    assert_eq!(store.load(), Ok(state.clone()));
    assert_eq!(
        store.complete_uninstall(&ArchProvisionState::Uninstalling(
            boothop_core::UninstallingRecord {
                operation_id: "test-uninstall".into(),
                operation_version: 1,
                owned_entry: ready_entry_for_tombstone(),
                step: UninstallingStep::UkiRemoved,
                residual: Vec::new(),
                boot_order_proof: Some(removal_proof(
                    "test-uninstall",
                    ready_entry_for_tombstone().boot_id,
                )),
            }
        )),
        Err(Error::NotConfigured)
    );
}

fn ready_entry_for_tombstone() -> boothop_core::OwnedArchEntry {
    match ready_state() {
        ArchProvisionState::Ready(entry) => entry,
        _ => unreachable!(),
    }
}

fn removal_proof(operation_id: &str, boot_id: boothop_core::BootId) -> BootOrderRemovalProof {
    BootOrderRemovalProof {
        operation_id: operation_id.into(),
        operation_version: 1,
        boot_id,
        before: BootOrderSnapshot {
            attributes: 7,
            ids: vec![boot_id],
        },
        expected_after: BootOrderSnapshot {
            attributes: 7,
            ids: vec![],
        },
        observed_after: Some(BootOrderSnapshot {
            attributes: 7,
            ids: vec![],
        }),
    }
}

#[test]
fn provisioning_after_tombstone_requires_a_new_operation_id() {
    let fs = FakeFs::installed();
    let tombstone = ArchProvisionState::Uninstalled(UninstalledRecord {
        operation_id: "old-operation".into(),
        operation_version: 1,
        owned_entry: ready_entry_for_tombstone(),
    });
    fs.set_journal(boothop_core::encode_arch_provision_state(&tombstone).unwrap());
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Ok(tombstone.clone()));
    let ArchProvisionState::Uninstalled(tombstone_record) = tombstone else {
        unreachable!()
    };
    let mut replay = pending_state();
    if let ArchProvisionState::Provisioning(record) = &mut replay {
        record.operation_id = tombstone_record.operation_id.clone();
    }
    assert_eq!(store.save(&replay), Err(Error::NotConfigured));
    if let ArchProvisionState::Provisioning(record) = &mut replay {
        record.operation_id = "new-operation".into();
    }
    store.save(&replay).unwrap();
    assert_eq!(store.load(), Ok(replay));
    assert!(fs.journal().is_some());
}

#[test]
fn generic_journal_save_cannot_alter_durable_boot_order_proof() {
    let fs = FakeFs::installed();
    let entry = ready_entry_for_tombstone();
    let state = ArchProvisionState::Uninstalling(boothop_core::UninstallingRecord {
        operation_id: "proof-op".into(),
        operation_version: 1,
        owned_entry: entry.clone(),
        step: UninstallingStep::BootOrderRemoved,
        residual: Vec::new(),
        boot_order_proof: Some(removal_proof("proof-op", entry.boot_id)),
    });
    fs.set_journal(boothop_core::encode_arch_provision_state(&state).unwrap());
    let original = fs.journal();
    let mut forged = state.clone();
    if let ArchProvisionState::Uninstalling(record) = &mut forged {
        record
            .boot_order_proof
            .as_mut()
            .unwrap()
            .observed_after
            .as_mut()
            .unwrap()
            .ids
            .push(boothop_core::BootId(99));
    }
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.save(&forged), Err(Error::NotConfigured));
    assert_eq!(fs.journal(), original);
}

fn pending_state() -> ArchProvisionState {
    let mut entry = match ready_state() {
        ArchProvisionState::Ready(entry) => entry,
        _ => unreachable!(),
    };
    entry.publish = None;
    ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: "test-provision".into(),
        operation_version: 1,
        owned_entry: entry,
        step: ProvisioningStep::UkiPublicationPending,
        residual: vec![],
    })
}

#[test]
fn journal_rejects_forged_ready_and_skipped_attempted_checkpoint() {
    let fs = FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();

    assert_eq!(store.save(&ready_state()), Err(Error::NotConfigured));
    assert!(fs.journal().is_none());
    let ArchProvisionState::Ready(entry) = ready_state() else {
        unreachable!()
    };
    let forged_tombstone = ArchProvisionState::Uninstalled(UninstalledRecord {
        operation_id: "fake-uninstall".into(),
        operation_version: 1,
        owned_entry: entry,
    });
    assert_eq!(store.save(&forged_tombstone), Err(Error::NotConfigured));
    assert!(fs.journal().is_none());

    let pending = pending_state();
    store.save(&pending).unwrap();

    let mut advanced = pending.clone();
    if let ArchProvisionState::Provisioning(record) = &mut advanced {
        record.step = ProvisioningStep::BootEntryCreateAttempted;
        record.owned_entry.publish = Some(boothop_core::PublishMetadata {
            sha256: [0x22; 32],
            size: 42,
        });
    }
    let old = fs.journal();
    assert_eq!(store.save(&advanced), Err(Error::NotConfigured));
    assert_eq!(fs.journal(), old);

    let mut attempted = pending_state();
    if let ArchProvisionState::Provisioning(record) = &mut attempted {
        record.step = ProvisioningStep::BootOrderAppendAttempted;
        record.owned_entry.publish = Some(boothop_core::PublishMetadata {
            sha256: [0x33; 32],
            size: 43,
        });
    }
    let attempted_fs = FakeFs::installed();
    attempted_fs.set_journal(boothop_core::encode_arch_provision_state(&attempted).unwrap());
    let mut attempted_store = ArchProvisionStore::acquire(attempted_fs.clone()).unwrap();
    if let ArchProvisionState::Provisioning(record) = &mut attempted {
        record.residual.push(Residual::BootOrderMayContainEntry);
    }
    attempted_store.save(&attempted).unwrap();
    let old = attempted_fs.journal();
    let mut residual_removed = attempted.clone();
    if let ArchProvisionState::Provisioning(record) = &mut residual_removed {
        record.residual.clear();
    }
    assert_eq!(
        attempted_store.save(&residual_removed),
        Err(Error::NotConfigured)
    );
    assert_eq!(attempted_fs.journal(), old);
}

#[test]
fn short_writes_complete_before_atomic_publish() {
    let fs = FakeFs::installed();
    fs.0.borrow_mut().write_limit = Some(3);
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let state = pending_state();
    store.save(&state).unwrap();
    assert_eq!(store.load(), Ok(state));
    assert_eq!(
        fs.0.borrow()
            .events
            .iter()
            .filter(|e| *e == "rename")
            .count(),
        1
    );
}

#[test]
fn file_and_directory_sync_failures_are_reported_with_journal_semantics() {
    for (stage, expected) in [
        (
            "temp_fsync",
            Error::PlatformIo {
                operation: PlatformOperation::Flush,
                raw_code: 5,
            },
        ),
        ("dir_fsync", Error::StoreDurabilityUnknown { raw_code: 5 }),
    ] {
        let fs = FakeFs::installed();
        fs.0.borrow_mut().fail = Some((stage, 5));
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        assert_eq!(store.save(&pending_state()), Err(expected));
        assert!(fs.journal().is_none() == (stage == "temp_fsync"));
    }
}

#[test]
fn unknown_journal_is_never_overwritten() {
    for (bytes, expected) in [
        (
            br#"{"version":999,"state":"Ready"}"#.to_vec(),
            Error::UnsupportedRecordVersion { found: 999 },
        ),
        (b"{broken".to_vec(), Error::CorruptRecord),
    ] {
        let fs = FakeFs::installed();
        fs.set_journal(bytes);
        let old = fs.journal();
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        assert_eq!(store.save(&ready_state()), Err(expected));
        assert_eq!(fs.journal(), old);
        assert!(!fs.0.borrow().events.iter().any(|e| e == "create"));
    }
}
