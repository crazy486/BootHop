#![cfg(target_os = "linux")]

use boothop_core::{
    ArchProvisionState, BootId, BootOrderRemovalProof, BootOrderSnapshot, OwnedArchEntry,
    UninstallingRecord, UninstallingStep,
};

#[allow(dead_code)]
mod support;
use boothop_core::encode_arch_provision_state;
use boothop_platform::linux::{
    arch_provision_store::ArchProvisionStore,
    boot_order::{
        BootOrderIo, BootOrderValue, OwnedBootEntryIo, begin_uninstall, observe_append_only,
        observe_entry_removal, observe_order_removal,
    },
    coordinator::{
        BootEntryCreatePermit, BootEntryRemovePermit, BootOrderAppendPermit, BootOrderRemovePermit,
        LifecycleBackend, LifecycleFailure, LifecycleProofBinding, LifecycleReadback,
        ProvisionIntent, UkiPublishPermit, UkiRemovePermit, provision, uninstall as run_uninstall,
    },
    owned_uki::{OwnedUkiIo, OwnedUkiState, observe_uki_removal},
    uki::{
        CmdlineSource, PreparedUkiArtifact, SecureBootPlan, UkiBuildBackend, UkiBuildError,
        UkiBuildPlan, UkiValidation, prepare_uki_artifact,
    },
};

fn entry() -> OwnedArchEntry {
    let ArchProvisionState::Ready(entry) = crate::support::ready_state() else {
        unreachable!()
    };
    entry
}

fn uninstall(step: UninstallingStep) -> ArchProvisionState {
    ArchProvisionState::Uninstalling(UninstallingRecord {
        operation_id: "phase4-test".into(),
        operation_version: 1,
        owned_entry: entry(),
        step,
        residual: Vec::new(),
        boot_order_proof: Some(BootOrderRemovalProof {
            operation_id: "phase4-test".into(),
            operation_version: 1,
            boot_id: entry().boot_id,
            before: BootOrderSnapshot {
                attributes: 7,
                ids: vec![BootId(9), entry().boot_id, BootId(4)],
            },
            expected_after: BootOrderSnapshot {
                attributes: 7,
                ids: vec![BootId(9), BootId(4)],
            },
            observed_after: Some(BootOrderSnapshot {
                attributes: 7,
                ids: vec![BootId(9), BootId(4)],
            }),
        }),
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
    order_change_on_bootnext_read: Option<(usize, Vec<u16>)>,
    boot_next_value: BootId,
    external_order_on_write: Option<Vec<u16>>,
    drift_after_prepare: bool,
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
            order_change_on_bootnext_read: None,
            boot_next_value: BootId(0x4444),
            external_order_on_write: None,
            drift_after_prepare: false,
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
        if let Some((at, _)) = &self.order_change_on_bootnext_read
            && *at == self.boot_next_reads
        {
            let (_, ids) = self.order_change_on_bootnext_read.take().unwrap();
            self.order = BootOrderValue::new(7, ids.into_iter().map(BootId).collect())?;
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

    fn append_boot_order(
        &mut self,
        permit: BootOrderAppendPermit<'_>,
        entry_io: &mut dyn OwnedBootEntryIo,
    ) -> Result<(), boothop_core::Error> {
        let before = match permit.precondition_evidence() {
            LifecycleProofBinding::BootEntryAndOrderBefore { order, .. } => order,
            _ => return Err(boothop_core::Error::NotConfigured),
        };
        if self.read_boot_next()?.is_some() {
            return Err(boothop_core::Error::Busy);
        }
        if self.order != *before {
            return Err(boothop_core::Error::ReadbackFailed);
        }
        let entry = permit.owned_entry();
        let actual = entry_io
            .read_boot_entry(entry.boot_id)?
            .ok_or(boothop_core::Error::TargetMissing)?;
        if actual != boothop_platform::linux::boot_order::owned_entry_bytes(&entry.identity)? {
            return Err(boothop_core::Error::IdentityMismatch);
        }
        let mut ids = before.ids.clone();
        ids.push(permit.owned_entry().boot_id);
        let value = BootOrderValue::new(before.attributes, ids)?;
        self.writes += 1;
        if self.fail_write {
            self.order = value;
            return Err(boothop_core::Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Write,
                raw_code: 5,
            });
        }
        if let Some(ids) = self.external_order_on_write.take() {
            self.order = BootOrderValue::new(7, ids.into_iter().map(BootId).collect()).unwrap();
            return Ok(());
        }
        self.order = value;
        if self.mutate_on_write {
            self.order.ids.push(BootId(0xeeee));
        }
        Ok(())
    }

    fn remove_boot_order(
        &mut self,
        permit: BootOrderRemovePermit<'_>,
        entry_io: &mut dyn OwnedBootEntryIo,
    ) -> Result<(), boothop_core::Error> {
        let before = match permit.precondition_evidence() {
            LifecycleProofBinding::BootEntryAndOrderBefore { order, .. } => order,
            _ => return Err(boothop_core::Error::NotConfigured),
        };
        let owned_id = permit.owned_entry().boot_id;
        if self.read_boot_next()?.is_some_and(|next| next == owned_id) {
            return Err(boothop_core::Error::Busy);
        }
        if self.order != *before {
            return Err(boothop_core::Error::ReadbackFailed);
        }
        let actual = entry_io
            .read_boot_entry(owned_id)?
            .ok_or(boothop_core::Error::TargetMissing)?;
        if actual
            != boothop_platform::linux::boot_order::owned_entry_bytes(
                &permit.owned_entry().identity,
            )?
        {
            return Err(boothop_core::Error::IdentityMismatch);
        }
        let value = BootOrderValue::new(
            before.attributes,
            before
                .ids
                .iter()
                .copied()
                .filter(|id| *id != owned_id)
                .collect(),
        )?;
        self.writes += 1;
        if self.fail_write {
            self.order = value;
            return Err(boothop_core::Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Write,
                raw_code: 5,
            });
        }
        if let Some(ids) = self.external_order_on_write.take() {
            self.order = BootOrderValue::new(7, ids.into_iter().map(BootId).collect()).unwrap();
            return Ok(());
        }
        self.order = value;
        if self.mutate_on_write {
            self.order.ids.push(BootId(0xeeee));
        }
        Ok(())
    }
}

#[test]
fn begin_uninstall_is_started_before_any_mutation() {
    let state = begin_uninstall(entry(), "op-1".into()).unwrap();
    assert!(
        matches!(state, ArchProvisionState::Uninstalling(record) if record.step == UninstallingStep::Started)
    );
}

#[derive(Default)]
struct FakeEntry {
    bytes: Option<Vec<u8>>,
    reads: usize,
    replacement_on_read: Option<(usize, Vec<u8>)>,
    deletes: usize,
    retain_after_delete: bool,
    fail_delete: bool,
    replacement_at_delete: Option<Vec<u8>>,
}

impl OwnedBootEntryIo for FakeEntry {
    fn read_boot_entry(&mut self, _id: BootId) -> Result<Option<Vec<u8>>, boothop_core::Error> {
        self.reads += 1;
        if self
            .replacement_on_read
            .as_ref()
            .is_some_and(|(at, _)| *at == self.reads)
        {
            self.bytes = self.replacement_on_read.take().map(|(_, bytes)| bytes);
        }
        Ok(self.bytes.clone())
    }

    fn delete_boot_entry_if_exact(
        &mut self,
        permit: BootEntryRemovePermit<'_>,
        boot: &mut dyn BootOrderIo,
    ) -> Result<(), boothop_core::Error> {
        let id = permit.owned_entry().boot_id;
        if boot.read_boot_next()?.is_some_and(|next| next == id) {
            return Err(boothop_core::Error::Busy);
        }
        let order = boot.read_boot_order()?;
        order.validate()?;
        if order.ids.contains(&id) {
            return Err(boothop_core::Error::Busy);
        }
        if let Some(replacement) = self.replacement_at_delete.take() {
            self.bytes = Some(replacement);
        }
        let expected =
            boothop_platform::linux::boot_order::owned_entry_bytes(&permit.owned_entry().identity)?;
        self.deletes += 1;
        if id != BootId(0x1234) || self.bytes.as_deref() != Some(expected.as_slice()) {
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
    replacement_before_remove: Option<OwnedUkiState>,
}

impl Default for FakeUki {
    fn default() -> Self {
        Self {
            state: OwnedUkiState::Missing,
            removes: 0,
            retain_after_remove: false,
            fail_remove: false,
            replacement_before_remove: None,
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
        permit: UkiRemovePermit<'_>,
    ) -> Result<(), boothop_core::Error> {
        if let Some(replacement) = self.replacement_before_remove.take() {
            self.state = replacement;
        }
        let metadata = permit
            .owned_entry()
            .publish
            .as_ref()
            .ok_or(boothop_core::Error::CorruptRecord)?;
        self.removes += 1;
        if self.fail_remove {
            return Err(boothop_core::Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Write,
                raw_code: 5,
            });
        }
        if self.state
            != (OwnedUkiState::Regular {
                sha256: metadata.sha256,
                size: metadata.size,
            })
        {
            return Err(boothop_core::Error::IdentityMismatch);
        }
        if !self.retain_after_remove {
            self.state = OwnedUkiState::Missing;
        }
        Ok(())
    }
}

struct AdapterBackend {
    entry: OwnedArchEntry,
    firmware: FakeFirmware,
    entry_io: FakeEntry,
    uki_io: FakeUki,
    readd_order_before_entry_delete: bool,
}

struct AdapterUkiBuilder;
impl UkiBuildBackend for AdapterUkiBuilder {
    fn build(&mut self, _: &UkiBuildPlan) -> Result<Vec<u8>, UkiBuildError> {
        Ok(b"order adapter UKI".to_vec())
    }
    fn validate(&mut self, _: &[u8], _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        Ok(())
    }
    fn sign_if_required(&mut self, _: &mut Vec<u8>, _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        Ok(())
    }
}

fn adapter_prepared_uki() -> PreparedUkiArtifact {
    let plan = UkiBuildPlan {
        kernel_flavor: "linux".into(),
        kernel_image: "/kernel".into(),
        initramfs_image: "/initramfs".into(),
        config_path: "/config".into(),
        preset_path: "/preset".into(),
        final_uki_path: "EFI/BootHop/arch.efi".into(),
        staged_uki_path: "EFI/BootHop/arch.efi.staging".into(),
        command_line_source: CmdlineSource::Preset,
        command_line: "root=UUID=test".into(),
        includes_microcode: false,
        secure_boot: SecureBootPlan {
            signing_required: false,
            signer_already_configured: false,
        },
        validation: UkiValidation {
            require_efi_application: true,
            require_kernel_section: true,
            require_initrd_section: true,
            require_cmdline_section: true,
            verify_after_signing: false,
        },
        inputs: Vec::new(),
    };
    prepare_uki_artifact(&plan, &mut AdapterUkiBuilder).unwrap()
}

impl AdapterBackend {
    fn new(entry: OwnedArchEntry, firmware: FakeFirmware) -> Self {
        let publish = entry.publish.as_ref().unwrap();
        Self {
            entry_io: FakeEntry {
                bytes: Some(
                    boothop_platform::linux::boot_order::owned_entry_bytes(&entry.identity)
                        .unwrap(),
                ),
                ..Default::default()
            },
            uki_io: FakeUki {
                state: OwnedUkiState::Regular {
                    sha256: publish.sha256,
                    size: publish.size,
                },
                ..Default::default()
            },
            entry,
            firmware,
            readd_order_before_entry_delete: false,
        }
    }

    fn verify_owned_entry(&mut self, entry: &OwnedArchEntry) -> Result<(), boothop_core::Error> {
        let actual = self
            .entry_io
            .read_boot_entry(entry.boot_id)?
            .ok_or(boothop_core::Error::TargetMissing)?;
        let expected = boothop_platform::linux::boot_order::owned_entry_bytes(&entry.identity)?;
        if actual != expected {
            return Err(boothop_core::Error::IdentityMismatch);
        }
        Ok(())
    }

    fn mutation_error(
        error: boothop_core::Error,
        crossed_write_boundary: bool,
        residual: boothop_core::Residual,
    ) -> LifecycleFailure {
        if crossed_write_boundary {
            LifecycleFailure::uncertain(error, residual)
        } else if error == boothop_core::Error::NotConfigured {
            LifecycleFailure::rejected(error)
        } else {
            LifecycleFailure::stopped(error, residual)
        }
    }
}

impl LifecycleBackend for AdapterBackend {
    fn prepare_uki_publication(
        &mut self,
        _entry: &OwnedArchEntry,
    ) -> Result<(PreparedUkiArtifact, LifecycleReadback), boothop_core::Error> {
        let prepared = adapter_prepared_uki();
        let metadata = prepared.metadata().clone();
        self.entry.publish = Some(metadata.clone());
        self.uki_io.state = OwnedUkiState::Regular {
            sha256: metadata.sha256,
            size: metadata.size,
        };
        Ok((prepared, LifecycleReadback::UkiAbsent))
    }

    fn publish_uki(
        &mut self,
        _artifact: PreparedUkiArtifact,
        permit: UkiPublishPermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        Ok(LifecycleReadback::UkiPresent(
            permit.owned_entry().publish.clone().unwrap(),
        ))
    }

    fn prepare_boot_entry(
        &mut self,
        _entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, boothop_core::Error> {
        Ok(LifecycleReadback::BootEntryAbsent)
    }

    fn create_boot_entry(
        &mut self,
        permit: BootEntryCreatePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        Ok(LifecycleReadback::BootEntryPresent(
            permit.owned_entry().identity.clone(),
        ))
    }

    fn prepare_boot_order_append(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, boothop_core::Error> {
        self.verify_owned_entry(entry)?;
        Ok(LifecycleReadback::BootEntryAndOrder {
            identity: entry.identity.clone(),
            order: self.firmware.order.clone(),
        })
    }

    fn append_boot_order(
        &mut self,
        permit: BootOrderAppendPermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        if self.firmware.drift_after_prepare {
            self.firmware.order.ids.push(BootId(0x7777));
            self.firmware.drift_after_prepare = false;
        }
        let writes = self.firmware.writes;
        boothop_platform::linux::boot_order::append_owned_entry(
            &mut self.firmware,
            &mut self.entry_io,
            permit,
        )
        .map_err(|error| {
            let residual = if matches!(
                error,
                boothop_core::Error::IdentityMismatch | boothop_core::Error::TargetMissing
            ) {
                boothop_core::Residual::BootEntryMayExist
            } else {
                boothop_core::Residual::BootOrderMayContainEntry
            };
            Self::mutation_error(error, self.firmware.writes != writes, residual)
        })?;
        Ok(LifecycleReadback::BootOrder(self.firmware.order.clone()))
    }

    fn prepare_boot_order_remove(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, boothop_core::Error> {
        self.verify_owned_entry(entry)?;
        Ok(LifecycleReadback::BootEntryAndOrder {
            identity: entry.identity.clone(),
            order: self.firmware.order.clone(),
        })
    }

    fn remove_boot_order(
        &mut self,
        permit: BootOrderRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        if self.firmware.drift_after_prepare {
            self.firmware.order.ids.push(BootId(0x7777));
            self.firmware.drift_after_prepare = false;
        }
        let writes = self.firmware.writes;
        boothop_platform::linux::boot_order::remove_owned_from_order(
            &mut self.firmware,
            &mut self.entry_io,
            permit,
        )
        .map_err(|error| {
            let residual = if matches!(
                error,
                boothop_core::Error::IdentityMismatch | boothop_core::Error::TargetMissing
            ) {
                boothop_core::Residual::BootEntryMayExist
            } else {
                boothop_core::Residual::BootOrderMayContainEntry
            };
            Self::mutation_error(error, self.firmware.writes != writes, residual)
        })?;
        Ok(LifecycleReadback::BootOrder(self.firmware.order.clone()))
    }

    fn prepare_boot_entry_remove(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, boothop_core::Error> {
        if self.readd_order_before_entry_delete {
            self.firmware.order_reads = 0;
            self.firmware.readd_on_second_order_read = true;
        }
        Ok(LifecycleReadback::BootEntryPresent(entry.identity.clone()))
    }

    fn remove_boot_entry(
        &mut self,
        permit: BootEntryRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        let deletes = self.entry_io.deletes;
        boothop_platform::linux::boot_order::remove_owned_entry(
            &mut self.entry_io,
            &mut self.firmware,
            permit,
        )
        .map_err(|error| {
            Self::mutation_error(
                error,
                self.entry_io.deletes != deletes,
                boothop_core::Residual::BootEntryMayExist,
            )
        })?;
        Ok(LifecycleReadback::BootEntryAbsent)
    }

    fn prepare_uki_remove(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, boothop_core::Error> {
        Ok(LifecycleReadback::UkiPresent(
            entry.publish.clone().unwrap(),
        ))
    }

    fn remove_uki(
        &mut self,
        permit: UkiRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        let removes = self.uki_io.removes;
        boothop_platform::linux::owned_uki::remove_owned_uki(&mut self.uki_io, permit).map_err(
            |error| {
                Self::mutation_error(
                    error,
                    self.uki_io.removes != removes,
                    boothop_core::Residual::UkiMayRemain,
                )
            },
        )?;
        Ok(LifecycleReadback::UkiAbsent)
    }

    fn observe(
        &mut self,
        _state: &ArchProvisionState,
    ) -> Result<LifecycleReadback, boothop_core::Error> {
        Err(boothop_core::Error::NotConfigured)
    }

    fn observe_uki_ownership(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, boothop_core::Error> {
        Ok(LifecycleReadback::UkiPresent(
            entry.publish.clone().unwrap(),
        ))
    }
}

#[test]
fn coordinator_permits_reach_only_the_matching_fake_lifecycle_writers() {
    let entry = entry();
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut backend = AdapterBackend::new(entry.clone(), FakeFirmware::with_order(&[9, 4]));
    let mut intent_entry = entry.clone();
    intent_entry.publish = None;
    let provisioned = provision(
        &mut store,
        &mut backend,
        ProvisionIntent {
            operation_id: "adapter-permit-provision".into(),
            owned_entry: intent_entry,
        },
    )
    .unwrap();
    assert!(matches!(provisioned, ArchProvisionState::Ready(_)));
    assert_eq!(
        backend.firmware.order.ids,
        [BootId(9), BootId(4), entry.boot_id]
    );
    assert_eq!(backend.firmware.writes, 1);

    drop(store);
    fs.set_journal(encode_arch_provision_state(&ArchProvisionState::Ready(entry.clone())).unwrap());
    let mut store = ArchProvisionStore::acquire(fs).unwrap();
    let mut backend = AdapterBackend::new(
        entry.clone(),
        FakeFirmware::with_order(&[BootId(9).0, entry.boot_id.0, 4]),
    );
    let removed =
        run_uninstall(&mut store, &mut backend, "adapter-permit-uninstall".into()).unwrap();
    assert!(matches!(removed, ArchProvisionState::Uninstalled(_)));
    assert_eq!(backend.firmware.order.ids, [BootId(9), BootId(4)]);
    assert_eq!(backend.firmware.writes, 1);
    assert_eq!(backend.entry_io.deletes, 1);
    assert_eq!(backend.entry_io.bytes, None);
    assert_eq!(backend.uki_io.removes, 1);
    assert_eq!(backend.uki_io.state, OwnedUkiState::Missing);
}

#[test]
fn coordinator_order_permits_reject_full_snapshot_drift_before_any_write() {
    let entry = entry();
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs).unwrap();
    let mut backend = AdapterBackend::new(entry.clone(), FakeFirmware::with_order(&[9, 4]));
    backend.firmware.drift_after_prepare = true;
    let mut intent_entry = entry.clone();
    intent_entry.publish = None;
    assert_eq!(
        provision(
            &mut store,
            &mut backend,
            ProvisionIntent {
                operation_id: "adapter-permit-drift".into(),
                owned_entry: intent_entry,
            },
        ),
        Err(boothop_core::Error::ReadbackFailed)
    );
    assert_eq!(backend.firmware.writes, 0);
    assert_eq!(
        backend.firmware.order.ids,
        [BootId(9), BootId(4), BootId(0x7777)]
    );
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Provisioning(record)
            if record.step == boothop_core::ProvisioningStep::BootOrderAppendAttempted
                && record.residual.contains(&boothop_core::Residual::BootOrderMayContainEntry)
    ));
}

#[test]
fn boot_order_write_races_and_uncertainty_keep_residual_and_never_retry() {
    for fault in ["writer-race", "write-error", "readback-mismatch"] {
        let entry = entry();
        let fs = support::FakeFs::installed();
        let mut store = ArchProvisionStore::acquire(fs).unwrap();
        let mut backend = AdapterBackend::new(entry.clone(), FakeFirmware::with_order(&[9, 4]));
        match fault {
            "writer-race" => {
                backend.firmware.external_order_on_write = Some(vec![9, 4, 0x7777]);
            }
            "write-error" => backend.firmware.fail_write = true,
            "readback-mismatch" => backend.firmware.mutate_on_write = true,
            _ => unreachable!(),
        }
        let mut intent_entry = entry.clone();
        intent_entry.publish = None;
        let intent = ProvisionIntent {
            operation_id: format!("adapter-{fault}"),
            owned_entry: intent_entry,
        };
        assert!(
            provision(&mut store, &mut backend, intent.clone()).is_err(),
            "{fault}"
        );
        assert!(
            matches!(
                store.load().unwrap(),
                ArchProvisionState::Provisioning(record)
                    if record.step == boothop_core::ProvisioningStep::BootOrderAppendAttempted
                        && record.residual.contains(&boothop_core::Residual::BootOrderMayContainEntry)
            ),
            "{fault}"
        );
        let writes = backend.firmware.writes;
        assert_eq!(writes, 1, "{fault}");

        // Recovery is read-only and a repeated request cannot replay a committed Attempted step.
        boothop_platform::linux::coordinator::recover(&mut store, &mut backend).unwrap();
        assert_eq!(backend.firmware.writes, writes, "{fault}");
        assert_eq!(
            provision(&mut store, &mut backend, intent),
            Err(boothop_core::Error::NotConfigured),
            "{fault}"
        );
        assert_eq!(backend.firmware.writes, writes, "{fault}");
    }
}

#[test]
fn final_bootnext_gate_blocks_boot_order_append_before_write() {
    let entry = entry();
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs).unwrap();
    let mut firmware = FakeFirmware::with_order(&[9, 4]);
    firmware.set_boot_next_on_read = Some(4);
    let mut backend = AdapterBackend::new(entry.clone(), firmware);
    let mut intent_entry = entry.clone();
    intent_entry.publish = None;

    assert_eq!(
        provision(
            &mut store,
            &mut backend,
            ProvisionIntent {
                operation_id: "append-next-race".into(),
                owned_entry: intent_entry,
            },
        ),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(backend.firmware.writes, 0);
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Provisioning(record)
            if record.step == boothop_core::ProvisioningStep::BootOrderAppendAttempted
                && record.residual.contains(&boothop_core::Residual::BootOrderMayContainEntry)
    ));
}

#[test]
fn uninstall_order_write_faults_stop_before_entry_and_uki_removal() {
    for fault in ["writer-race", "write-error", "readback-mismatch"] {
        let entry = entry();
        let (_fs, mut store) = ready_store(&entry);
        let mut firmware = FakeFirmware::with_order(&[9, entry.boot_id.0, 4]);
        match fault {
            "writer-race" => {
                firmware.external_order_on_write = Some(vec![9, entry.boot_id.0, 4, 0x7777]);
            }
            "write-error" => firmware.fail_write = true,
            "readback-mismatch" => firmware.mutate_on_write = true,
            _ => unreachable!(),
        }
        let mut backend = AdapterBackend::new(entry.clone(), firmware);

        assert!(
            run_uninstall(&mut store, &mut backend, format!("uninstall-order-{fault}")).is_err(),
            "{fault}"
        );
        assert_eq!(backend.firmware.writes, 1, "{fault}");
        assert_eq!(backend.entry_io.deletes, 0, "{fault}");
        assert_eq!(backend.uki_io.removes, 0, "{fault}");
        assert!(
            matches!(
                store.load().unwrap(),
                ArchProvisionState::Uninstalling(record)
                    if record.step == UninstallingStep::BootOrderRemovalAttempted
                        && record.residual.contains(&boothop_core::Residual::BootOrderMayContainEntry)
            ),
            "{fault}"
        );
        assert_eq!(
            run_uninstall(
                &mut store,
                &mut backend,
                "uninstall-order-retry-must-stop".into()
            ),
            Err(boothop_core::Error::NotConfigured),
            "{fault}"
        );
        assert_eq!(backend.firmware.writes, 1, "{fault}");
    }
}

#[test]
fn bootnext_set_at_order_writer_boundary_stops_append_and_removal() {
    let entry = entry();
    let fs = support::FakeFs::installed();
    let mut provision_store = ArchProvisionStore::acquire(fs).unwrap();
    let mut append_firmware = FakeFirmware::with_order(&[9, 4]);
    append_firmware.set_boot_next_on_read = Some(4);
    append_firmware.boot_next_value = BootId(0x5555);
    let mut append_backend = AdapterBackend::new(entry.clone(), append_firmware);
    let mut intent_entry = entry.clone();
    intent_entry.publish = None;
    assert_eq!(
        provision(
            &mut provision_store,
            &mut append_backend,
            ProvisionIntent {
                operation_id: "append-next-at-writer".into(),
                owned_entry: intent_entry,
            },
        ),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(append_backend.firmware.writes, 0);
    assert!(matches!(
        provision_store.load().unwrap(),
        ArchProvisionState::Provisioning(record)
            if record.step == boothop_core::ProvisioningStep::BootOrderAppendAttempted
                && record.residual.contains(&boothop_core::Residual::BootOrderMayContainEntry)
    ));

    let (_fs, mut uninstall_store) = ready_store(&entry);
    let mut remove_firmware = FakeFirmware::with_order(&[9, entry.boot_id.0, 4]);
    remove_firmware.set_boot_next_on_read = Some(4);
    remove_firmware.boot_next_value = entry.boot_id;
    let mut remove_backend = AdapterBackend::new(entry.clone(), remove_firmware);
    assert_eq!(
        run_uninstall(
            &mut uninstall_store,
            &mut remove_backend,
            "remove-next-at-writer".into()
        ),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(remove_backend.firmware.writes, 0);
    assert_eq!(remove_backend.entry_io.deletes, 0);
    assert_eq!(remove_backend.uki_io.removes, 0);
    assert!(matches!(
        uninstall_store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootOrderRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::BootOrderMayContainEntry)
    ));
}

#[test]
fn boot_entry_delete_error_or_bad_readback_is_residual_without_retry() {
    for fault in ["write-error", "readback-still-present"] {
        let entry = entry();
        let (_fs, mut store) = ready_store(&entry);
        let mut backend = AdapterBackend::new(
            entry.clone(),
            FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
        );
        match fault {
            "write-error" => backend.entry_io.fail_delete = true,
            "readback-still-present" => backend.entry_io.retain_after_delete = true,
            _ => unreachable!(),
        }

        assert!(run_uninstall(&mut store, &mut backend, format!("entry-{fault}")).is_err());
        assert_eq!(backend.entry_io.deletes, 1, "{fault}");
        assert_eq!(backend.uki_io.removes, 0, "{fault}");
        assert!(
            matches!(
                store.load().unwrap(),
                ArchProvisionState::Uninstalling(record)
                    if record.step == UninstallingStep::BootEntryRemovalAttempted
                        && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
            ),
            "{fault}"
        );
        assert_eq!(
            run_uninstall(&mut store, &mut backend, "entry-retry-must-stop".into()),
            Err(boothop_core::Error::NotConfigured),
            "{fault}"
        );
        assert_eq!(backend.entry_io.deletes, 1, "{fault}");
    }
}

#[test]
fn uki_missing_or_non_regular_target_is_residual_and_never_deleted() {
    for state in [
        OwnedUkiState::Missing,
        OwnedUkiState::Symlink,
        OwnedUkiState::Other,
    ] {
        let entry = entry();
        let (_fs, mut store) = ready_store(&entry);
        let mut backend = AdapterBackend::new(
            entry.clone(),
            FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
        );
        backend.uki_io.state = state.clone();

        assert_eq!(
            run_uninstall(&mut store, &mut backend, "uninstall-non-regular-uki".into()),
            Err(match state {
                OwnedUkiState::Missing => boothop_core::Error::TargetMissing,
                _ => boothop_core::Error::IdentityMismatch,
            })
        );
        assert_eq!(backend.uki_io.state, state);
        assert_eq!(backend.uki_io.removes, 0);
        assert!(matches!(
            store.load().unwrap(),
            ArchProvisionState::Uninstalling(record)
                if record.step == UninstallingStep::UkiRemovalAttempted
                    && record.residual.contains(&boothop_core::Residual::UkiMayRemain)
        ));
    }
}

#[test]
fn uki_delete_error_or_bad_readback_stays_residual_without_retry() {
    for fault in ["write-error", "readback-still-present"] {
        let entry = entry();
        let (_fs, mut store) = ready_store(&entry);
        let mut backend = AdapterBackend::new(
            entry.clone(),
            FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
        );
        match fault {
            "write-error" => backend.uki_io.fail_remove = true,
            "readback-still-present" => backend.uki_io.retain_after_remove = true,
            _ => unreachable!(),
        }

        assert!(run_uninstall(&mut store, &mut backend, format!("uki-{fault}")).is_err());
        assert_eq!(backend.uki_io.removes, 1, "{fault}");
        assert!(
            matches!(
                store.load().unwrap(),
                ArchProvisionState::Uninstalling(record)
                    if record.step == UninstallingStep::UkiRemovalAttempted
                        && record.residual.contains(&boothop_core::Residual::UkiMayRemain)
            ),
            "{fault}"
        );
        assert_eq!(
            run_uninstall(&mut store, &mut backend, "uki-retry-must-stop".into()),
            Err(boothop_core::Error::NotConfigured),
            "{fault}"
        );
        assert_eq!(backend.uki_io.removes, 1, "{fault}");
    }
}

#[test]
fn boot_order_values_reject_malformed_attributes_and_duplicate_ids() {
    assert_eq!(
        BootOrderValue::new(6, vec![BootId(1)]),
        Err(boothop_core::Error::UnsupportedFormat)
    );
    assert_eq!(
        BootOrderValue::new(7, vec![BootId(1), BootId(1)]),
        Err(boothop_core::Error::UnsupportedFormat)
    );
}

fn ready_store(entry: &OwnedArchEntry) -> (support::FakeFs, ArchProvisionStore<support::FakeFs>) {
    let fs = support::FakeFs::installed();
    fs.set_journal(encode_arch_provision_state(&ArchProvisionState::Ready(entry.clone())).unwrap());
    let store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    (fs, store)
}

#[test]
fn uninstall_stops_on_boot_order_drift_with_residual_and_no_later_deletes() {
    let entry = entry();
    let (_fs, mut store) = ready_store(&entry);
    let mut backend = AdapterBackend::new(
        entry.clone(),
        FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
    );
    backend.firmware.drift_after_prepare = true;

    assert_eq!(
        run_uninstall(&mut store, &mut backend, "uninstall-order-drift".into()),
        Err(boothop_core::Error::ReadbackFailed)
    );
    assert_eq!(backend.firmware.writes, 0);
    assert_eq!(backend.entry_io.deletes, 0);
    assert_eq!(backend.uki_io.removes, 0);
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootOrderRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::BootOrderMayContainEntry)
    ));
}

#[test]
fn order_append_rechecks_boot_entry_ownership_at_the_write_boundary() {
    let entry = entry();
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs).unwrap();
    let mut backend = AdapterBackend::new(entry.clone(), FakeFirmware::with_order(&[9, 4]));
    let foreign = b"foreign bytes replaced after prepare".to_vec();
    backend.entry_io.replacement_on_read = Some((3, foreign.clone()));
    let mut intent_entry = entry.clone();
    intent_entry.publish = None;

    assert_eq!(
        provision(
            &mut store,
            &mut backend,
            ProvisionIntent {
                operation_id: "append-entry-race".into(),
                owned_entry: intent_entry,
            },
        ),
        Err(boothop_core::Error::IdentityMismatch)
    );
    assert_eq!(backend.firmware.writes, 0);
    assert_eq!(backend.firmware.order.ids, [BootId(9), BootId(4)]);
    assert_eq!(backend.entry_io.bytes, Some(foreign));
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Provisioning(record)
            if record.step == boothop_core::ProvisioningStep::BootOrderAppendAttempted
                && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
    ));
}

#[test]
fn order_removal_rechecks_boot_entry_ownership_at_the_write_boundary() {
    let entry = entry();
    let (_fs, mut store) = ready_store(&entry);
    let mut backend = AdapterBackend::new(
        entry.clone(),
        FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
    );
    let foreign = b"foreign bytes replaced after prepare".to_vec();
    backend.entry_io.replacement_on_read = Some((3, foreign.clone()));

    assert_eq!(
        run_uninstall(&mut store, &mut backend, "remove-entry-race".into()),
        Err(boothop_core::Error::IdentityMismatch)
    );
    assert_eq!(backend.firmware.writes, 0);
    assert_eq!(
        backend.firmware.order.ids,
        [BootId(9), entry.boot_id, BootId(4)]
    );
    assert_eq!(backend.entry_io.bytes, Some(foreign));
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootOrderRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
    ));
}

#[test]
fn uninstall_preserves_replaced_non_owned_boot_entry() {
    let entry = entry();
    let (_fs, mut store) = ready_store(&entry);
    let mut backend = AdapterBackend::new(
        entry.clone(),
        FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
    );
    let foreign = b"foreign Boot#### bytes".to_vec();
    backend.entry_io.bytes = Some(foreign.clone());

    assert_eq!(
        run_uninstall(&mut store, &mut backend, "uninstall-foreign-entry".into()),
        Err(boothop_core::Error::IdentityMismatch)
    );
    assert_eq!(
        backend.firmware.order.ids,
        [BootId(9), entry.boot_id, BootId(4)]
    );
    assert_eq!(backend.firmware.writes, 0);
    assert_eq!(backend.entry_io.deletes, 0);
    assert_eq!(backend.entry_io.bytes, Some(foreign));
    assert_eq!(backend.uki_io.removes, 0);
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::Started
                && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
    ));
    assert_eq!(
        run_uninstall(&mut store, &mut backend, "retry-must-stop".into()),
        Err(boothop_core::Error::NotConfigured)
    );
    assert_eq!(backend.entry_io.deletes, 0);
    assert_eq!(backend.uki_io.removes, 0);
}

#[test]
fn exact_boot_entry_delete_boundary_keeps_a_racing_foreign_replacement() {
    let entry = entry();
    let (_fs, mut store) = ready_store(&entry);
    let mut backend = AdapterBackend::new(
        entry.clone(),
        FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
    );
    let foreign = b"replacement at unlink boundary".to_vec();
    backend.entry_io.replacement_at_delete = Some(foreign.clone());

    assert_eq!(
        run_uninstall(&mut store, &mut backend, "uninstall-entry-race".into()),
        Err(boothop_core::Error::IdentityMismatch)
    );
    assert_eq!(backend.entry_io.bytes, Some(foreign));
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootEntryRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
    ));
    assert_eq!(backend.uki_io.removes, 0);
}

#[test]
fn final_boot_order_reference_check_prevents_boot_entry_delete() {
    let entry = entry();
    let (_fs, mut store) = ready_store(&entry);
    let mut backend = AdapterBackend::new(
        entry.clone(),
        FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
    );
    backend.readd_order_before_entry_delete = true;

    assert_eq!(
        run_uninstall(&mut store, &mut backend, "uninstall-order-readd".into()),
        Err(boothop_core::Error::Busy)
    );
    assert!(backend.firmware.order.ids.contains(&entry.boot_id));
    assert_eq!(backend.entry_io.deletes, 0);
    assert_eq!(backend.uki_io.removes, 0);
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootEntryRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
    ));
}

#[test]
fn final_bootnext_check_prevents_boot_entry_delete() {
    let entry = entry();
    let (_fs, mut store) = ready_store(&entry);
    let mut firmware = FakeFirmware::with_order(&[9, entry.boot_id.0, 4]);
    // Order removal consumes three BootNext reads; the entry adapter performs three more.
    firmware.set_boot_next_on_read = Some(6);
    firmware.boot_next_value = entry.boot_id;
    let mut backend = AdapterBackend::new(entry.clone(), firmware);

    assert_eq!(
        run_uninstall(&mut store, &mut backend, "uninstall-next-race".into()),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(backend.entry_io.deletes, 0);
    assert_eq!(backend.uki_io.removes, 0);
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootEntryRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
    ));
}

#[test]
fn bootentry_delete_boundary_rechecks_bootnext_and_bootorder() {
    let entry = entry();
    let (_fs, mut next_store) = ready_store(&entry);
    let mut next_firmware = FakeFirmware::with_order(&[9, entry.boot_id.0, 4]);
    // The operation's pre-delete checks consume reads 5–7; the delete writer rechecks at 8.
    next_firmware.set_boot_next_on_read = Some(8);
    next_firmware.boot_next_value = entry.boot_id;
    let mut next_backend = AdapterBackend::new(entry.clone(), next_firmware);
    assert_eq!(
        run_uninstall(
            &mut next_store,
            &mut next_backend,
            "delete-next-writer-race".into()
        ),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(next_backend.entry_io.deletes, 0);
    assert_eq!(next_backend.uki_io.removes, 0);
    assert!(matches!(
        next_store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootEntryRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
    ));

    let (_fs, mut order_store) = ready_store(&entry);
    let mut order_firmware = FakeFirmware::with_order(&[9, entry.boot_id.0, 4]);
    order_firmware.order_change_on_bootnext_read = Some((8, vec![9, entry.boot_id.0, 4]));
    let mut order_backend = AdapterBackend::new(entry.clone(), order_firmware);
    assert_eq!(
        run_uninstall(
            &mut order_store,
            &mut order_backend,
            "delete-order-writer-race".into()
        ),
        Err(boothop_core::Error::Busy)
    );
    assert_eq!(
        order_backend.firmware.order.ids,
        [BootId(9), entry.boot_id, BootId(4)]
    );
    assert_eq!(order_backend.entry_io.deletes, 0);
    assert_eq!(order_backend.uki_io.removes, 0);
    assert!(matches!(
        order_store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootEntryRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::BootEntryMayExist)
    ));
}

#[test]
fn uninstall_preserves_mismatched_uki_and_does_not_retry() {
    let entry = entry();
    let (_fs, mut store) = ready_store(&entry);
    let mut backend = AdapterBackend::new(
        entry.clone(),
        FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
    );
    backend.uki_io.state = OwnedUkiState::Regular {
        sha256: [0x99; 32],
        size: 100,
    };
    let foreign = backend.uki_io.state.clone();

    assert_eq!(
        run_uninstall(&mut store, &mut backend, "uninstall-foreign-uki".into()),
        Err(boothop_core::Error::IdentityMismatch)
    );
    assert_eq!(backend.firmware.order.ids, [BootId(9), BootId(4)]);
    assert_eq!(backend.entry_io.deletes, 1);
    assert_eq!(backend.uki_io.state, foreign);
    assert_eq!(backend.uki_io.removes, 0);
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::UkiRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::UkiMayRemain)
    ));
    assert_eq!(
        run_uninstall(&mut store, &mut backend, "retry-must-stop".into()),
        Err(boothop_core::Error::NotConfigured)
    );
    assert_eq!(backend.uki_io.removes, 0);
}

#[test]
fn exact_uki_delete_boundary_keeps_a_racing_foreign_replacement() {
    let entry = entry();
    let (_fs, mut store) = ready_store(&entry);
    let mut backend = AdapterBackend::new(
        entry.clone(),
        FakeFirmware::with_order(&[9, entry.boot_id.0, 4]),
    );
    let foreign = OwnedUkiState::Regular {
        sha256: [0x99; 32],
        size: 99,
    };
    backend.uki_io.replacement_before_remove = Some(foreign.clone());

    assert_eq!(
        run_uninstall(&mut store, &mut backend, "uninstall-uki-race".into()),
        Err(boothop_core::Error::IdentityMismatch)
    );
    assert_eq!(backend.uki_io.state, foreign);
    assert_eq!(backend.uki_io.removes, 1);
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::UkiRemovalAttempted
                && record.residual.contains(&boothop_core::Residual::UkiMayRemain)
    ));
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
