#![cfg(target_os = "linux")]

use boothop_core::{
    ArchProvisionState, BootId, OwnedArchEntry, ProvisioningRecord, ProvisioningStep,
    PublishMetadata, Residual, UninstallingRecord, UninstallingStep,
};

#[allow(dead_code)]
mod support;
use boothop_platform::linux::{
    arch_provision_store::ArchProvisionStore,
    boot_order::{
        BootOrderIo, BootOrderValue, OwnedBootEntryIo, append_owned_entry, begin_uninstall,
        observe_append_only, observe_entry_removal, observe_order_removal, owned_entry_bytes,
        remove_owned_entry, remove_owned_from_order, verify_order_absent_before_entry_delete,
    },
    owned_uki::{
        OwnedUkiIo, OwnedUkiState, digest_and_size, observe_uki_removal, remove_owned_uki,
    },
};

fn entry() -> OwnedArchEntry {
    let ArchProvisionState::Ready(entry) = crate::support::ready_state() else {
        unreachable!()
    };
    entry
}

fn provisioning(step: ProvisioningStep) -> ArchProvisionState {
    ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: "phase4-test".into(),
        operation_version: 1,
        owned_entry: entry(),
        step,
        residual: Vec::new(),
    })
}

fn uninstall(step: UninstallingStep) -> ArchProvisionState {
    ArchProvisionState::Uninstalling(UninstallingRecord {
        operation_id: "phase4-test".into(),
        operation_version: 1,
        owned_entry: entry(),
        step,
        residual: Vec::new(),
    })
}

struct FakeFirmware {
    next: Option<BootId>,
    order: BootOrderValue,
    writes: usize,
    mutate_on_write: bool,
    fail_write: bool,
    order_reads: usize,
    readd_on_second_order_read: bool,
    boot_next_reads: usize,
    set_boot_next_on_read: Option<usize>,
    boot_next_value: BootId,
    external_order_on_write: Option<Vec<u16>>,
}

impl Default for FakeFirmware {
    fn default() -> Self {
        Self {
            next: None,
            order: BootOrderValue::new(7, Vec::new()).unwrap(),
            writes: 0,
            mutate_on_write: false,
            fail_write: false,
            order_reads: 0,
            readd_on_second_order_read: false,
            boot_next_reads: 0,
            set_boot_next_on_read: None,
            boot_next_value: BootId(0x4444),
            external_order_on_write: None,
        }
    }
}

impl FakeFirmware {
    fn with_order(ids: &[u16]) -> Self {
        Self {
            order: BootOrderValue::new(7, ids.iter().copied().map(BootId).collect()).unwrap(),
            ..Self::default()
        }
    }
}

impl BootOrderIo for FakeFirmware {
    fn read_boot_next(&mut self) -> Result<Option<BootId>, boothop_core::Error> {
        self.boot_next_reads += 1;
        if self.set_boot_next_on_read == Some(self.boot_next_reads) {
            self.next = Some(self.boot_next_value);
        }
        Ok(self.next)
    }

    fn read_boot_order(&mut self) -> Result<BootOrderValue, boothop_core::Error> {
        self.order_reads += 1;
        if self.readd_on_second_order_read && self.order_reads == 2 {
            self.order.ids.push(BootId(0x1234));
        }
        Ok(self.order.clone())
    }

    fn write_boot_order(&mut self, value: &BootOrderValue) -> Result<(), boothop_core::Error> {
        self.writes += 1;
        if self.fail_write {
            self.order = value.clone();
            return Err(boothop_core::Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Write,
                raw_code: 5,
            });
        }
        if let Some(ids) = self.external_order_on_write.take() {
            self.order = BootOrderValue::new(7, ids.into_iter().map(BootId).collect()).unwrap();
            return Ok(());
        }
        self.order = value.clone();
        if self.mutate_on_write {
            self.order.ids.push(BootId(0xeeee));
        }
        Ok(())
    }
}

#[test]
fn append_is_tail_only_and_preserves_existing_relative_order() {
    let mut firmware = FakeFirmware::with_order(&[0, 7, 3]);
    let mut state = provisioning(ProvisioningStep::BootOrderAppendAttempted);
    append_owned_entry(&mut firmware, &mut state).unwrap();
    assert_eq!(
        firmware.order.ids,
        [BootId(0), BootId(7), BootId(3), BootId(0x1234)]
    );
    assert_eq!(firmware.writes, 1);
    assert!(
        matches!(state, ArchProvisionState::Provisioning(ref record) if record.step == ProvisioningStep::BootOrderReadBackVerified)
    );
}

#[test]
fn append_rejects_duplicate_malformed_or_busy_inputs_without_writing() {
    let mut duplicate = FakeFirmware::with_order(&[0x1234]);
    let mut state = provisioning(ProvisioningStep::BootOrderAppendAttempted);
    assert_eq!(
        append_owned_entry(&mut duplicate, &mut state),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(duplicate.writes, 0);

    let mut busy = FakeFirmware::with_order(&[1, 2]);
    busy.next = Some(BootId(99));
    assert_eq!(
        append_owned_entry(&mut busy, &mut state),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(busy.writes, 0);

    assert_eq!(
        BootOrderValue::new(6, vec![BootId(1)]),
        Err(boothop_core::Error::UnsupportedFormat)
    );
    assert_eq!(
        BootOrderValue::new(7, vec![BootId(1), BootId(1)]),
        Err(boothop_core::Error::UnsupportedFormat)
    );
}

#[test]
fn append_readback_mismatch_is_residual_and_is_never_retried() {
    let mut firmware = FakeFirmware::with_order(&[1, 2]);
    firmware.mutate_on_write = true;
    let mut state = provisioning(ProvisioningStep::BootOrderAppendAttempted);
    assert_eq!(
        append_owned_entry(&mut firmware, &mut state),
        Err(boothop_core::Error::ReadbackFailed)
    );
    assert_eq!(firmware.writes, 1);
    assert!(
        matches!(state, ArchProvisionState::Provisioning(ref record) if record.step == ProvisioningStep::BootOrderAppendAttempted)
    );
    if let ArchProvisionState::Provisioning(record) = &mut state {
        record.residual.push(Residual::BootOrderMayContainEntry);
    }
    assert_eq!(
        append_owned_entry(&mut firmware, &mut state),
        Err(boothop_core::Error::NotConfigured)
    );
    assert_eq!(firmware.writes, 1);
}

#[test]
fn residual_checkpoint_blocks_bootorder_write_and_removal_retry() {
    let mut firmware = FakeFirmware::with_order(&[1, 2]);
    let mut append_state = provisioning(ProvisioningStep::BootOrderAppendAttempted);
    if let ArchProvisionState::Provisioning(record) = &mut append_state {
        record.residual.push(Residual::BootOrderMayContainEntry);
    }
    assert_eq!(
        append_owned_entry(&mut firmware, &mut append_state),
        Err(boothop_core::Error::NotConfigured)
    );
    assert_eq!(firmware.writes, 0);

    let mut removal_firmware = FakeFirmware::with_order(&[9, 0x1234]);
    let mut removal_state = uninstall(UninstallingStep::BootOrderRemovalAttempted);
    if let ArchProvisionState::Uninstalling(record) = &mut removal_state {
        record.residual.push(Residual::BootOrderMayContainEntry);
    }
    assert_eq!(
        remove_owned_from_order(&mut removal_firmware, &mut removal_state),
        Err(boothop_core::Error::NotConfigured)
    );
    assert_eq!(removal_firmware.writes, 0);
}

#[test]
fn uncertain_append_and_order_removal_keep_attempted_checkpoint() {
    let mut firmware = FakeFirmware::with_order(&[1, 2]);
    firmware.fail_write = true;
    let mut append_state = provisioning(ProvisioningStep::BootOrderAppendAttempted);
    assert!(append_owned_entry(&mut firmware, &mut append_state).is_err());
    assert!(
        matches!(append_state, ArchProvisionState::Provisioning(ref record) if record.step == ProvisioningStep::BootOrderAppendAttempted)
    );

    let mut removal_firmware = FakeFirmware::with_order(&[9, 0x1234]);
    removal_firmware.fail_write = true;
    let mut removal_state = uninstall(UninstallingStep::BootOrderRemovalAttempted);
    assert!(remove_owned_from_order(&mut removal_firmware, &mut removal_state).is_err());
    assert!(
        matches!(removal_state, ArchProvisionState::Uninstalling(ref record) if record.step == UninstallingStep::BootOrderRemovalAttempted)
    );
}

#[test]
fn final_bootnext_gate_blocks_append_and_removal() {
    let mut append_firmware = FakeFirmware::with_order(&[1, 2]);
    append_firmware.set_boot_next_on_read = Some(3);
    let mut append_state = provisioning(ProvisioningStep::BootOrderAppendAttempted);
    assert_eq!(
        append_owned_entry(&mut append_firmware, &mut append_state),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(append_firmware.writes, 0);

    let mut removal_firmware = FakeFirmware::with_order(&[9, 0x1234]);
    removal_firmware.set_boot_next_on_read = Some(3);
    removal_firmware.boot_next_value = BootId(0x1234);
    let mut removal_state = uninstall(UninstallingStep::BootOrderRemovalAttempted);
    assert_eq!(
        remove_owned_from_order(&mut removal_firmware, &mut removal_state),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(removal_firmware.writes, 0);
}

#[test]
fn external_writer_winning_the_append_or_removal_write_stops_on_readback_mismatch() {
    let mut append_firmware = FakeFirmware::with_order(&[1, 2]);
    append_firmware.external_order_on_write = Some(vec![1, 2, 0x7777]);
    let mut append_state = provisioning(ProvisioningStep::BootOrderAppendAttempted);
    assert_eq!(
        append_owned_entry(&mut append_firmware, &mut append_state),
        Err(boothop_core::Error::ReadbackFailed)
    );
    assert_eq!(append_firmware.writes, 1);

    let mut removal_firmware = FakeFirmware::with_order(&[9, 0x1234]);
    removal_firmware.external_order_on_write = Some(vec![9, 0x1234, 0x7777]);
    let mut removal_state = uninstall(UninstallingStep::BootOrderRemovalAttempted);
    assert_eq!(
        remove_owned_from_order(&mut removal_firmware, &mut removal_state),
        Err(boothop_core::Error::ReadbackFailed)
    );
    assert_eq!(removal_firmware.writes, 1);
}

#[test]
fn begin_uninstall_is_started_before_any_mutation() {
    let state = begin_uninstall(entry(), "op-1".into()).unwrap();
    assert!(
        matches!(state, ArchProvisionState::Uninstalling(record) if record.step == UninstallingStep::Started)
    );
}

#[test]
fn uninstall_removes_only_owned_id_and_rechecks_before_entry_delete() {
    let mut firmware = FakeFirmware::with_order(&[9, 0x1234, 4]);
    let mut state = uninstall(UninstallingStep::BootOrderRemovalAttempted);
    remove_owned_from_order(&mut firmware, &mut state).unwrap();
    assert_eq!(firmware.order.ids, [BootId(9), BootId(4)]);
    assert_eq!(firmware.writes, 1);
    verify_order_absent_before_entry_delete(&mut firmware, &state).unwrap();

    let mut blocked = FakeFirmware::with_order(&[9, 0x1234]);
    blocked.next = Some(BootId(0x1234));
    let mut blocked_state = uninstall(UninstallingStep::BootOrderRemovalAttempted);
    assert_eq!(
        remove_owned_from_order(&mut blocked, &mut blocked_state),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(blocked.writes, 0);
}

#[test]
fn entry_delete_rechecks_boot_order_at_the_final_boundary() {
    let owned = owned_entry_bytes(&entry().identity).unwrap();
    let mut entry_io = FakeEntry {
        bytes: Some(owned),
        ..Default::default()
    };
    let mut firmware = FakeFirmware::with_order(&[9]);
    firmware.readd_on_second_order_read = true;
    let mut state = uninstall(UninstallingStep::BootEntryRemovalAttempted);
    assert_eq!(
        remove_owned_entry(&mut entry_io, &mut firmware, &mut state),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(entry_io.deletes, 0);
}

#[derive(Default)]
struct FakeEntry {
    bytes: Option<Vec<u8>>,
    deletes: usize,
    retain_after_delete: bool,
    fail_delete: bool,
}

impl OwnedBootEntryIo for FakeEntry {
    fn read_boot_entry(&mut self, _id: BootId) -> Result<Option<Vec<u8>>, boothop_core::Error> {
        Ok(self.bytes.clone())
    }

    fn delete_boot_entry_if_exact(
        &mut self,
        _id: BootId,
        expected: &[u8],
    ) -> Result<(), boothop_core::Error> {
        self.deletes += 1;
        if self.bytes.as_deref() != Some(expected) {
            return Err(boothop_core::Error::IdentityMismatch);
        }
        if self.fail_delete {
            return Err(boothop_core::Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Write,
                raw_code: 5,
            });
        }
        if !self.retain_after_delete {
            self.bytes = None;
        }
        Ok(())
    }
}

#[test]
fn entry_delete_requires_exact_owned_bytes_and_exact_readback() {
    let owned = owned_entry_bytes(&entry().identity).unwrap();
    let mut entry_io = FakeEntry {
        bytes: Some(owned),
        ..Default::default()
    };
    let mut firmware = FakeFirmware::with_order(&[9]);
    let mut state = uninstall(UninstallingStep::BootEntryRemovalAttempted);
    remove_owned_entry(&mut entry_io, &mut firmware, &mut state).unwrap();
    assert_eq!(entry_io.deletes, 1);
    assert!(
        matches!(state, ArchProvisionState::Uninstalling(ref record) if record.step == UninstallingStep::BootEntryRemovalReadBackVerified)
    );

    let mut changed = FakeEntry {
        bytes: Some(vec![7, 0, 0, 0]),
        ..Default::default()
    };
    let mut changed_state = uninstall(UninstallingStep::BootEntryRemovalAttempted);
    assert_eq!(
        remove_owned_entry(&mut changed, &mut firmware, &mut changed_state),
        Err(boothop_core::Error::IdentityMismatch)
    );
    assert_eq!(changed.deletes, 0);

    let mut retained = FakeEntry {
        bytes: Some(owned_entry_bytes(&entry().identity).unwrap()),
        retain_after_delete: true,
        ..Default::default()
    };
    let mut retained_state = uninstall(UninstallingStep::BootEntryRemovalAttempted);
    assert_eq!(
        remove_owned_entry(&mut retained, &mut firmware, &mut retained_state),
        Err(boothop_core::Error::ReadbackFailed)
    );
    assert_eq!(retained.deletes, 1);
    assert!(
        matches!(retained_state, ArchProvisionState::Uninstalling(ref record) if record.step == UninstallingStep::BootEntryRemovalAttempted)
    );
    if let ArchProvisionState::Uninstalling(record) = &mut retained_state {
        record.residual.push(Residual::BootEntryMayExist);
    }
    assert_eq!(
        remove_owned_entry(&mut retained, &mut firmware, &mut retained_state),
        Err(boothop_core::Error::NotConfigured)
    );
    assert_eq!(retained.deletes, 1);

    let mut failed = FakeEntry {
        bytes: Some(owned_entry_bytes(&entry().identity).unwrap()),
        fail_delete: true,
        ..Default::default()
    };
    let mut failed_state = uninstall(UninstallingStep::BootEntryRemovalAttempted);
    assert!(remove_owned_entry(&mut failed, &mut firmware, &mut failed_state).is_err());
    assert!(
        matches!(failed_state, ArchProvisionState::Uninstalling(ref record) if record.step == UninstallingStep::BootEntryRemovalAttempted)
    );
}

#[test]
fn reconciliation_paths_are_read_only_and_never_retry_mutations() {
    let mut firmware = FakeFirmware::with_order(&[1, 2]);
    assert!(!observe_append_only(&mut firmware, BootId(0x1234)).unwrap());
    assert_eq!(firmware.writes, 0);

    let order_state = uninstall(UninstallingStep::BootOrderRemovalWriteCompleted);
    assert!(observe_order_removal(&mut firmware, &order_state).unwrap());
    assert_eq!(firmware.writes, 0);

    let mut entry_io = FakeEntry {
        bytes: None,
        ..Default::default()
    };
    let entry_state = uninstall(UninstallingStep::BootEntryDeleteCompleted);
    assert!(observe_entry_removal(&mut entry_io, &entry_state).unwrap());
    assert_eq!(entry_io.deletes, 0);

    let mut uki = FakeUki::default();
    let uki_state = uninstall(UninstallingStep::UkiDeleteCompleted);
    assert_eq!(
        observe_uki_removal(&mut uki, &uki_state).unwrap(),
        OwnedUkiState::Missing
    );
    assert_eq!(uki.removes, 0);
}

struct FakeUki {
    state: OwnedUkiState,
    removes: usize,
    retain_after_remove: bool,
    fail_remove: bool,
}

impl Default for FakeUki {
    fn default() -> Self {
        Self {
            state: OwnedUkiState::Missing,
            removes: 0,
            retain_after_remove: false,
            fail_remove: false,
        }
    }
}

impl OwnedUkiIo for FakeUki {
    fn inspect_fixed(&mut self, path: &str) -> Result<OwnedUkiState, boothop_core::Error> {
        assert_eq!(path, "EFI/BootHop/arch.efi");
        Ok(self.state.clone())
    }
    fn remove_fixed_if_expected(
        &mut self,
        path: &str,
        sha256: [u8; 32],
        size: u64,
    ) -> Result<(), boothop_core::Error> {
        assert_eq!(path, "EFI/BootHop/arch.efi");
        self.removes += 1;
        if self.fail_remove {
            return Err(boothop_core::Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Write,
                raw_code: 5,
            });
        }
        if self.state != (OwnedUkiState::Regular { sha256, size }) {
            return Err(boothop_core::Error::IdentityMismatch);
        }
        if !self.retain_after_remove {
            self.state = OwnedUkiState::Missing;
        }
        Ok(())
    }
}

#[test]
fn uki_delete_requires_regular_exact_hash_and_size() {
    let bytes = b"owned uki";
    let (sha256, size) = digest_and_size(bytes);
    let mut state = uninstall(UninstallingStep::UkiRemovalAttempted);
    if let ArchProvisionState::Uninstalling(record) = &mut state {
        record.owned_entry.publish = Some(PublishMetadata { sha256, size });
    }
    let mut uki = FakeUki {
        state: OwnedUkiState::Regular { sha256, size },
        ..Default::default()
    };
    remove_owned_uki(&mut uki, &mut state).unwrap();
    assert_eq!(uki.removes, 1);

    let mut mismatch = FakeUki {
        state: OwnedUkiState::Symlink,
        ..Default::default()
    };
    let mut mismatch_state = uninstall(UninstallingStep::UkiRemovalAttempted);
    if let ArchProvisionState::Uninstalling(record) = &mut mismatch_state {
        record.owned_entry.publish = Some(PublishMetadata { sha256, size });
    }
    assert_eq!(
        remove_owned_uki(&mut mismatch, &mut mismatch_state),
        Err(boothop_core::Error::IdentityMismatch)
    );
    assert_eq!(mismatch.removes, 0);

    let mut retained = FakeUki {
        state: OwnedUkiState::Regular { sha256, size },
        retain_after_remove: true,
        ..Default::default()
    };
    let mut retained_state = uninstall(UninstallingStep::UkiRemovalAttempted);
    if let ArchProvisionState::Uninstalling(record) = &mut retained_state {
        record.owned_entry.publish = Some(PublishMetadata { sha256, size });
    }
    assert_eq!(
        remove_owned_uki(&mut retained, &mut retained_state),
        Err(boothop_core::Error::ReadbackFailed)
    );
    assert_eq!(retained.removes, 1);
    assert!(
        matches!(retained_state, ArchProvisionState::Uninstalling(ref record) if record.step == UninstallingStep::UkiRemovalAttempted)
    );
    if let ArchProvisionState::Uninstalling(record) = &mut retained_state {
        record.residual.push(Residual::UkiMayRemain);
    }
    assert_eq!(
        remove_owned_uki(&mut retained, &mut retained_state),
        Err(boothop_core::Error::NotConfigured)
    );
    assert_eq!(retained.removes, 1);

    let mut failed = FakeUki {
        state: OwnedUkiState::Regular { sha256, size },
        fail_remove: true,
        ..Default::default()
    };
    let mut failed_state = uninstall(UninstallingStep::UkiRemovalAttempted);
    if let ArchProvisionState::Uninstalling(record) = &mut failed_state {
        record.owned_entry.publish = Some(PublishMetadata { sha256, size });
    }
    assert!(remove_owned_uki(&mut failed, &mut failed_state).is_err());
    assert!(
        matches!(failed_state, ArchProvisionState::Uninstalling(ref record) if record.step == UninstallingStep::UkiRemovalAttempted)
    );
}

#[test]
fn journal_is_removed_only_after_the_final_uki_checkpoint() {
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut complete = uninstall(UninstallingStep::UkiRemoved);
    if let ArchProvisionState::Uninstalling(record) = &mut complete {
        record.residual.clear();
    }
    // Seed the already verified terminal checkpoint; the transition guard is covered by the
    // ArchProvisionStore tests, while this test focuses on tombstone replacement.
    fs.set_journal(boothop_core::encode_arch_provision_state(&complete).unwrap());
    store.complete_uninstall(&complete).unwrap();
    assert!(matches!(
        store.load(),
        Ok(ArchProvisionState::Uninstalled(_))
    ));
}

#[test]
fn tombstone_survives_directory_sync_uncertainty() {
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut complete = uninstall(UninstallingStep::UkiRemoved);
    if let ArchProvisionState::Uninstalling(record) = &mut complete {
        record.residual.clear();
    }
    fs.set_journal(boothop_core::encode_arch_provision_state(&complete).unwrap());
    fs.0.borrow_mut().fail = Some(("dir_fsync", 5));
    assert_eq!(
        store.complete_uninstall(&complete),
        Err(boothop_core::Error::StoreDurabilityUnknown { raw_code: 5 })
    );
    assert!(matches!(
        store.load(),
        Ok(ArchProvisionState::Uninstalled(_))
    ));
}
