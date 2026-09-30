//! Narrow, journal-gated BootOrder lifecycle operations.
//!
//! This module deliberately does not use [`LinuxCalls`].  The production helper will
//! supply an implementation backed by a locked efivarfs directory; tests supply an
//! in-memory fake.  Keeping the operation boundary typed prevents these mutations from
//! becoming another generic `Platform::write_next` capability.

use super::coordinator::{
    BootEntryRemovePermit, BootOrderAppendPermit, BootOrderRemovePermit, LifecycleProofBinding,
};
use boothop_core::{
    ArchProvisionState, BootId, CanonicalIdentity, Error, OwnedArchEntry, UninstallingRecord,
    UninstallingStep, arch_uki_load_option_from_identity, serialize_load_option,
};

const EFI_VARIABLE_NON_VOLATILE: u32 = 1;
const EFI_VARIABLE_BOOTSERVICE_ACCESS: u32 = 2;
const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 4;
const BOOT_ATTRIBUTES: u32 =
    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
const MAX_BOOT_ORDER_ITEMS: usize = 65_536;

/// A decoded BootOrder with its attributes retained for strict validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootOrderValue {
    pub attributes: u32,
    pub ids: Vec<BootId>,
}

impl BootOrderValue {
    pub fn new(attributes: u32, ids: Vec<BootId>) -> Result<Self, Error> {
        let value = Self { attributes, ids };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.attributes != BOOT_ATTRIBUTES || self.ids.len() > MAX_BOOT_ORDER_ITEMS {
            return Err(Error::UnsupportedFormat);
        }
        let mut seen = vec![false; 65_536];
        for id in &self.ids {
            let slot = &mut seen[id.0 as usize];
            if *slot {
                return Err(Error::UnsupportedFormat);
            }
            *slot = true;
        }
        Ok(())
    }

    pub(crate) fn appended(&self, id: BootId) -> Result<Self, Error> {
        self.validate()?;
        if self.ids.contains(&id) || self.ids.len() == MAX_BOOT_ORDER_ITEMS {
            return Err(Error::Busy);
        }
        let mut ids = self.ids.clone();
        ids.push(id);
        Self::new(self.attributes, ids)
    }

    pub(crate) fn without(&self, id: BootId) -> Result<Self, Error> {
        self.validate()?;
        if !self.ids.contains(&id) {
            return Err(Error::TargetMissing);
        }
        Self::new(
            self.attributes,
            self.ids
                .iter()
                .copied()
                .filter(|candidate| *candidate != id)
                .collect(),
        )
    }
}

/// Decode the raw efivarfs representation of BootOrder.
///
/// efivarfs prefixes the variable payload with its four-byte EFI attributes field. This
/// parser accepts only the attributes and payload shape used by firmware BootOrder values;
/// malformed or ambiguous values are rejected before they can enter lifecycle operations.
pub fn decode_boot_order(raw: &[u8]) -> Result<BootOrderValue, Error> {
    let attributes = raw
        .get(..4)
        .and_then(|header| <[u8; 4]>::try_from(header).ok())
        .map(u32::from_le_bytes)
        .ok_or(Error::UnsupportedFormat)?;
    if attributes != BOOT_ATTRIBUTES {
        return Err(Error::UnsupportedFormat);
    }

    let payload = &raw[4..];
    if !payload.len().is_multiple_of(2) {
        return Err(Error::UnsupportedFormat);
    }
    let count = payload.len() / 2;
    if count > MAX_BOOT_ORDER_ITEMS {
        return Err(Error::ResourceLimit);
    }

    let mut ids = Vec::new();
    ids.try_reserve_exact(count)
        .map_err(|_| Error::ResourceLimit)?;
    ids.extend(
        payload
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| BootId(u16::from_le_bytes([pair[0], pair[1]]))),
    );
    BootOrderValue::new(attributes, ids)
}

/// The only firmware capabilities required by the BootOrder use case.
pub trait BootOrderIo {
    fn read_boot_next(&mut self) -> Result<Option<BootId>, Error>;
    fn read_boot_order(&mut self) -> Result<BootOrderValue, Error>;
    /// At the write boundary recheck the full BootOrder, BootNext, and exact owned Boot####.
    /// UEFI variables do not provide compare-and-swap, so this is best effort; implementations
    /// must read back and report residual state on mismatch, without retry or rollback.
    fn append_boot_order(
        &mut self,
        permit: BootOrderAppendPermit<'_>,
        entry_io: &mut dyn OwnedBootEntryIo,
    ) -> Result<(), Error>;
    /// At the write boundary recheck the full BootOrder, BootNext, and exact owned Boot####.
    /// UEFI variables do not provide compare-and-swap, so this is best effort; implementations
    /// must read back and report residual state on mismatch, without retry or rollback.
    fn remove_boot_order(
        &mut self,
        permit: BootOrderRemovePermit<'_>,
        entry_io: &mut dyn OwnedBootEntryIo,
    ) -> Result<(), Error>;
}

/// The separate, exact owned-entry deletion boundary.
pub trait OwnedBootEntryIo {
    fn read_boot_entry(&mut self, id: BootId) -> Result<Option<Vec<u8>>, Error>;
    /// Recheck BootNext, BootOrder, and exact owned bytes at the deletion boundary; never delete
    /// by ID alone. EFI has no atomic multi-variable transaction, so any observed mismatch must
    /// stop with residual state and the remaining check/write interval is best effort.
    fn delete_boot_entry_if_exact(
        &mut self,
        permit: BootEntryRemovePermit<'_>,
        boot: &mut dyn BootOrderIo,
    ) -> Result<(), Error>;
}

/// Starts uninstall in memory.  The caller must durably save this result while holding the
/// ownership journal lock before invoking any operation below.
pub fn begin_uninstall(
    entry: OwnedArchEntry,
    operation_id: String,
) -> Result<ArchProvisionState, Error> {
    if operation_id.is_empty()
        || operation_id.len() > 128
        || operation_id.chars().any(char::is_control)
    {
        return Err(Error::CorruptRecord);
    }
    Ok(ArchProvisionState::Uninstalling(UninstallingRecord {
        operation_id,
        operation_version: 1,
        owned_entry: entry,
        step: UninstallingStep::Started,
        residual: Vec::new(),
        boot_order_proof: None,
    }))
}

/// Append exactly one owned ID at the tail.  The journal must already contain the durable
/// `BootOrderAppendAttempted` checkpoint.  There is one final read and one write attempt;
/// mismatched readback is residual state and never triggers rollback or retry.
pub fn append_owned_entry<I: BootOrderIo>(
    io: &mut I,
    entry_io: &mut impl OwnedBootEntryIo,
    permit: BootOrderAppendPermit<'_>,
) -> Result<(), Error> {
    let (id, identity, before) = validate_append_permit(&permit)?;

    if io.read_boot_next()?.is_some() {
        return Err(Error::Busy);
    }
    // This observation catches a preexisting owned ID and malformed/duplicate order before the
    // final read.  It is intentionally not reused for the write after an external change.
    let initial = io.read_boot_order()?;
    initial.validate()?;
    if initial.ids.contains(&id) {
        return Err(Error::Busy);
    }
    if io.read_boot_next()?.is_some() {
        return Err(Error::Busy);
    }
    let latest = io.read_boot_order()?;
    latest.validate()?;
    if latest != before {
        return Err(Error::ReadbackFailed);
    }
    let expected = latest.appended(id)?;
    let current_entry = entry_io.read_boot_entry(id)?.ok_or(Error::TargetMissing)?;
    if current_entry != owned_entry_bytes(&identity)? {
        return Err(Error::IdentityMismatch);
    }
    if io.read_boot_next()?.is_some() {
        return Err(Error::Busy);
    }
    io.append_boot_order(permit, entry_io)?;
    let actual = io.read_boot_order()?;
    actual.validate()?;
    if actual != expected {
        return Err(Error::ReadbackFailed);
    }
    Ok(())
}

/// Observe an uncertain append after restart.  It never writes and never infers ownership from
/// presence alone; the caller retains the attempted journal checkpoint and residual.
pub fn observe_append_only<I: BootOrderIo>(io: &mut I, id: BootId) -> Result<bool, Error> {
    let order = io.read_boot_order()?;
    order.validate()?;
    Ok(order.ids.contains(&id))
}

/// Reconcile an interrupted BootOrder removal without writing or inferring who changed it.
/// `true` means the owned ID is absent from the current valid order.
pub fn observe_order_removal<I: BootOrderIo>(
    io: &mut I,
    state: &ArchProvisionState,
) -> Result<bool, Error> {
    let id = match state {
        ArchProvisionState::Uninstalling(record)
            if matches!(
                record.step,
                UninstallingStep::BootOrderRemovalAttempted
                    | UninstallingStep::BootOrderRemovalWriteCompleted
                    | UninstallingStep::BootOrderRemoved
                    | UninstallingStep::BootOrderRemovalReadBackVerified
            ) =>
        {
            record.owned_entry.boot_id
        }
        _ => return Err(Error::NotConfigured),
    };
    let order = io.read_boot_order()?;
    order.validate()?;
    Ok(!order.ids.contains(&id))
}

/// Remove the owned ID from the latest valid order.  The caller must save
/// `BootOrderRemovalAttempted` before this call.
pub fn remove_owned_from_order<I: BootOrderIo, E: OwnedBootEntryIo>(
    io: &mut I,
    entry_io: &mut E,
    permit: BootOrderRemovePermit<'_>,
) -> Result<(), Error> {
    let (id, identity, before) = validate_remove_order_permit(&permit)?;
    if io.read_boot_next()?.is_some_and(|next| next == id) {
        return Err(Error::Busy);
    }
    let current = io.read_boot_order()?;
    current.validate()?;
    if io.read_boot_next()?.is_some_and(|next| next == id) {
        return Err(Error::Busy);
    }
    let latest = io.read_boot_order()?;
    latest.validate()?;
    if latest != before {
        return Err(Error::ReadbackFailed);
    }
    let expected = latest.without(id)?;
    let current_entry = entry_io.read_boot_entry(id)?.ok_or(Error::TargetMissing)?;
    if current_entry != owned_entry_bytes(&identity)? {
        return Err(Error::IdentityMismatch);
    }
    if io.read_boot_next()?.is_some_and(|next| next == id) {
        return Err(Error::Busy);
    }
    io.remove_boot_order(permit, entry_io)?;
    let actual = io.read_boot_order()?;
    actual.validate()?;
    if actual != expected {
        return Err(Error::ReadbackFailed);
    }
    Ok(())
}

/// Final order/BootNext proof immediately before deleting Boot####.
pub fn verify_order_absent_before_entry_delete<I: BootOrderIo>(
    io: &mut I,
    state: &ArchProvisionState,
) -> Result<(), Error> {
    let id = uninstall_id(state, UninstallingStep::BootOrderRemovalReadBackVerified)?;
    if io.read_boot_next()?.is_some_and(|next| next == id) {
        return Err(Error::Busy);
    }
    let order = io.read_boot_order()?;
    order.validate()?;
    if order.ids.contains(&id) {
        return Err(Error::Busy);
    }
    Ok(())
}

fn uninstall_id(state: &ArchProvisionState, expected: UninstallingStep) -> Result<BootId, Error> {
    match state {
        ArchProvisionState::Uninstalling(record)
            if record.step == expected && record.residual.is_empty() =>
        {
            Ok(record.owned_entry.boot_id)
        }
        _ => Err(Error::NotConfigured),
    }
}

/// Remove only the exact bytes generated from the journaled fixed identity.  The caller must
/// save `BootEntryRemovalAttempted` before invoking this operation.  A delete that returns an
/// error is never retried here.
pub fn remove_owned_entry<I: OwnedBootEntryIo, B: BootOrderIo>(
    io: &mut I,
    boot: &mut B,
    permit: BootEntryRemovePermit<'_>,
) -> Result<(), Error> {
    let entry = validate_entry_remove_permit(&permit)?;
    let entry_id = entry.boot_id;
    let entry_identity = entry.identity.clone();
    if boot.read_boot_next()?.is_some_and(|next| next == entry_id) {
        return Err(Error::Busy);
    }
    let expected = owned_entry_bytes(&entry_identity)?;
    let actual = io.read_boot_entry(entry_id)?.ok_or(Error::TargetMissing)?;
    if actual != expected {
        return Err(Error::IdentityMismatch);
    }
    if boot.read_boot_next()?.is_some_and(|next| next == entry_id) {
        return Err(Error::Busy);
    }
    let order = boot.read_boot_order()?;
    order.validate()?;
    if order.ids.contains(&entry_id) {
        return Err(Error::Busy);
    }
    let boundary = io.read_boot_entry(entry_id)?.ok_or(Error::TargetMissing)?;
    if boundary != expected {
        return Err(Error::IdentityMismatch);
    }
    let final_order = boot.read_boot_order()?;
    final_order.validate()?;
    if final_order.ids.contains(&entry_id) {
        return Err(Error::Busy);
    }
    if boot.read_boot_next()?.is_some_and(|next| next == entry_id) {
        return Err(Error::Busy);
    }
    io.delete_boot_entry_if_exact(permit, boot)?;
    if io.read_boot_entry(entry_id)?.is_some() {
        return Err(Error::ReadbackFailed);
    }
    Ok(())
}

/// Reconcile an interrupted Boot#### removal without deleting or retrying it.
pub fn observe_entry_removal<I: OwnedBootEntryIo>(
    io: &mut I,
    state: &ArchProvisionState,
) -> Result<bool, Error> {
    let id = match state {
        ArchProvisionState::Uninstalling(record)
            if matches!(
                record.step,
                UninstallingStep::BootEntryRemovalAttempted
                    | UninstallingStep::BootEntryDeleteCompleted
                    | UninstallingStep::BootEntryRemoved
                    | UninstallingStep::BootEntryRemovalReadBackVerified
            ) =>
        {
            record.owned_entry.boot_id
        }
        _ => return Err(Error::NotConfigured),
    };
    Ok(io.read_boot_entry(id)?.is_none())
}

pub fn owned_entry_bytes(identity: &CanonicalIdentity) -> Result<Vec<u8>, Error> {
    let option = arch_uki_load_option_from_identity(identity)?;
    let payload = serialize_load_option(&option)?;
    let mut value = Vec::with_capacity(payload.len() + 4);
    value.extend_from_slice(&BOOT_ATTRIBUTES.to_le_bytes());
    value.extend_from_slice(&payload);
    Ok(value)
}

fn validate_append_permit(
    permit: &BootOrderAppendPermit<'_>,
) -> Result<(BootId, CanonicalIdentity, BootOrderValue), Error> {
    let entry = validate_provisioning_order_permit(
        permit.operation_id(),
        permit.operation_version(),
        permit.owned_entry(),
        permit.attempted_state(),
        boothop_core::ProvisioningStep::BootOrderAppendAttempted,
    )?;
    let (expected_identity, expected_before, observed_identity, observed_before) =
        match (permit.expected_evidence(), permit.precondition_evidence()) {
            (
                LifecycleProofBinding::BootEntryAndOrderBefore {
                    identity: expected_identity,
                    order: expected_order,
                },
                LifecycleProofBinding::BootEntryAndOrderBefore {
                    identity: observed_identity,
                    order: observed_order,
                },
            ) => (
                expected_identity,
                expected_order,
                observed_identity,
                observed_order,
            ),
            _ => return Err(Error::NotConfigured),
        };
    expected_before.validate()?;
    if expected_identity != observed_identity
        || expected_identity != &entry.identity
        || expected_before != observed_before
        || expected_before.ids.contains(&entry.boot_id)
    {
        return Err(Error::IdentityMismatch);
    }
    Ok((
        entry.boot_id,
        expected_identity.clone(),
        expected_before.clone(),
    ))
}

fn validate_remove_order_permit(
    permit: &BootOrderRemovePermit<'_>,
) -> Result<(BootId, CanonicalIdentity, BootOrderValue), Error> {
    let entry = validate_uninstall_order_permit(
        permit.operation_id(),
        permit.operation_version(),
        permit.owned_entry(),
        permit.attempted_state(),
        UninstallingStep::BootOrderRemovalAttempted,
    )?;
    let (expected_identity, expected_before, observed_identity, observed_before) =
        match (permit.expected_evidence(), permit.precondition_evidence()) {
            (
                LifecycleProofBinding::BootEntryAndOrderBefore {
                    identity: expected_identity,
                    order: expected_order,
                },
                LifecycleProofBinding::BootEntryAndOrderBefore {
                    identity: observed_identity,
                    order: observed_order,
                },
            ) => (
                expected_identity,
                expected_order,
                observed_identity,
                observed_order,
            ),
            _ => return Err(Error::NotConfigured),
        };
    expected_before.validate()?;
    if expected_identity != observed_identity
        || expected_identity != &entry.identity
        || expected_before != observed_before
        || !expected_before.ids.contains(&entry.boot_id)
    {
        return Err(Error::IdentityMismatch);
    }
    Ok((
        entry.boot_id,
        expected_identity.clone(),
        expected_before.clone(),
    ))
}

fn validate_entry_remove_permit(
    permit: &BootEntryRemovePermit<'_>,
) -> Result<OwnedArchEntry, Error> {
    let entry = validate_uninstall_order_permit(
        permit.operation_id(),
        permit.operation_version(),
        permit.owned_entry(),
        permit.attempted_state(),
        UninstallingStep::BootEntryRemovalAttempted,
    )?;
    if permit.expected_evidence() != &LifecycleProofBinding::BootEntryAbsent
        || permit.precondition_evidence() != &LifecycleProofBinding::BootEntryPresent
    {
        return Err(Error::IdentityMismatch);
    }
    Ok(entry.clone())
}

fn validate_provisioning_order_permit<'a>(
    operation_id: &str,
    operation_version: u64,
    entry: &'a OwnedArchEntry,
    attempted_state: &ArchProvisionState,
    expected_step: boothop_core::ProvisioningStep,
) -> Result<&'a OwnedArchEntry, Error> {
    let ArchProvisionState::Provisioning(record) = attempted_state else {
        return Err(Error::NotConfigured);
    };
    if record.step != expected_step
        || !record.residual.is_empty()
        || record.operation_id != operation_id
        || record.operation_version != operation_version
        || record.owned_entry != *entry
    {
        return Err(Error::IdentityMismatch);
    }
    Ok(entry)
}

fn validate_uninstall_order_permit<'a>(
    operation_id: &str,
    operation_version: u64,
    entry: &'a OwnedArchEntry,
    attempted_state: &ArchProvisionState,
    expected_step: UninstallingStep,
) -> Result<&'a OwnedArchEntry, Error> {
    let ArchProvisionState::Uninstalling(record) = attempted_state else {
        return Err(Error::NotConfigured);
    };
    if record.step != expected_step
        || !record.residual.is_empty()
        || record.operation_id != operation_id
        || record.operation_version != operation_version
        || record.owned_entry != *entry
    {
        return Err(Error::IdentityMismatch);
    }
    Ok(entry)
}
