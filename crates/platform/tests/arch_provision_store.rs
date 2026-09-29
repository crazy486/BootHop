#![cfg(target_os = "linux")]
mod support;

use boothop_core::{ArchProvisionState, Error, PlatformOperation};
use boothop_platform::linux::arch_provision_store::ArchProvisionStore;
use support::*;

#[test]
fn missing_journal_is_unprovisioned_and_ready_state_is_saved_separately() {
    let fs = FakeFs::installed();
    fs.set_record(boothop_core::encode_record(&target()).unwrap());
    let ordinary_record = fs.record();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Ok(ArchProvisionState::Unprovisioned));
    store.save(&ready_state()).unwrap();
    assert_eq!(store.load(), Ok(ready_state()));
    assert_eq!(fs.record(), ordinary_record); // ownership data never enters ordinary target records
    assert!(fs.journal().is_some());
}

#[test]
fn short_writes_complete_before_atomic_publish() {
    let fs = FakeFs::installed();
    fs.0.borrow_mut().write_limit = Some(3);
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    store.save(&ready_state()).unwrap();
    assert_eq!(store.load(), Ok(ready_state()));
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
        assert_eq!(store.save(&ready_state()), Err(expected));
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
