//! Trusted Arch provisioning and uninstall coordination.
//!
//! This is deliberately a small, injected boundary.  The coordinator owns the journal guard
//! for the complete operation and only accepts postconditions returned by a trusted backend.
//! No implementation in this module opens firmware, an ESP, or a system configuration file.

use super::arch_provision_store::ArchProvisionStore;
use super::store::Filesystem;
use boothop_core::{
    ArchProvisionState, Error, OwnedArchEntry, ProvisioningRecord, ProvisioningStep,
    PublishMetadata, Residual, UninstallingRecord, UninstallingStep,
};

/// A readback supplied by a trusted, narrowly scoped lifecycle adapter.
///
/// The enum intentionally carries no path, raw EFI bytes, or caller-selected Boot ID.  The
/// owned identity is taken only from the journal state held by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleReadback {
    UkiAbsent,
    UkiPresent(PublishMetadata),
    BootEntryAbsent,
    BootEntryPresent,
    BootOrderContains,
    BootOrderAbsent,
}

/// A mutation failure says whether the mutation was rejected before its write boundary or may
/// have crossed it.  Possible partial mutations are retained at the attempted checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleFailure {
    Rejected(Error),
    Uncertain { error: Error, residual: Residual },
}

impl LifecycleFailure {
    pub fn rejected(error: Error) -> Self {
        Self::Rejected(error)
    }

    pub fn uncertain(error: Error, residual: Residual) -> Self {
        Self::Uncertain { error, residual }
    }

    fn error(&self) -> Error {
        match self {
            Self::Rejected(error) | Self::Uncertain { error, .. } => error.clone(),
        }
    }
}

/// A complete explicit provision intent.  The helper supplies this from trusted discovery;
/// GUI input is never accepted by this API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionIntent {
    pub operation_id: String,
    pub owned_entry: OwnedArchEntry,
}

/// The injected platform boundary used by the coordinator.  Each prepare method performs the
/// exact readback needed to establish the pre-mutation proof.  Each mutation method performs
/// one write/delete at most and returns an exact readback; it must never retry or roll back.
pub trait LifecycleBackend {
    fn prepare_uki_publication(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<(PublishMetadata, LifecycleReadback), Error>;
    fn publish_uki(
        &mut self,
        entry: &OwnedArchEntry,
        expected: &PublishMetadata,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_boot_entry(&mut self, entry: &OwnedArchEntry) -> Result<LifecycleReadback, Error>;
    fn create_boot_entry(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_boot_order_append(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error>;
    fn append_boot_order(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_boot_order_remove(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error>;
    fn remove_boot_order(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_boot_entry_remove(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error>;
    fn remove_boot_entry(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_uki_remove(&mut self, entry: &OwnedArchEntry) -> Result<LifecycleReadback, Error>;
    fn remove_uki(&mut self, entry: &OwnedArchEntry)
    -> Result<LifecycleReadback, LifecycleFailure>;

    /// Restart reconciliation is read-only.  It must not call any mutation method.
    fn observe(&mut self, state: &ArchProvisionState) -> Result<LifecycleReadback, Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProofBinding {
    UkiAbsent,
    Uki(PublishMetadata),
    BootEntryAbsent,
    BootEntryPresent,
    BootOrderContains,
    BootOrderAbsent,
}

/// Private proof object.  Its fields and constructor are crate-private; callers can only obtain
/// one through coordinator code after an exact prepare/readback comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleProof {
    prior: ArchProvisionState,
    next: ArchProvisionState,
    operation_id: String,
    owned_entry: OwnedArchEntry,
    expected: ProofBinding,
    observed: ProofBinding,
}

impl LifecycleProof {
    fn new(
        prior: ArchProvisionState,
        next: ArchProvisionState,
        expected: ProofBinding,
        observed: ProofBinding,
    ) -> Result<Self, Error> {
        let (operation_id, owned_entry) = operation_and_entry(&prior)?;
        Ok(Self {
            prior,
            next,
            operation_id,
            owned_entry,
            expected,
            observed,
        })
    }

    pub(crate) fn next(&self) -> &ArchProvisionState {
        &self.next
    }

    pub(crate) fn validate(&self, current: &ArchProvisionState) -> Result<(), Error> {
        if current != &self.prior {
            return Err(Error::NotConfigured);
        }
        let (operation_id, owned_entry) = match &self.next {
            ArchProvisionState::Ready(entry) => (self.operation_id.clone(), entry.clone()),
            _ => operation_and_entry(&self.next)?,
        };
        if operation_id != self.operation_id
            || !same_owned_identity(&owned_entry, &self.owned_entry)
        {
            return Err(Error::IdentityMismatch);
        }
        if (matches!(self.next, ArchProvisionState::Ready(_)) || is_verified_step(&self.next))
            && self.expected != self.observed
        {
            return Err(Error::ReadbackFailed);
        }
        if !valid_proof_transition(&self.prior, &self.next) {
            return Err(Error::NotConfigured);
        }
        Ok(())
    }
}

fn operation_and_entry(state: &ArchProvisionState) -> Result<(String, OwnedArchEntry), Error> {
    match state {
        ArchProvisionState::Provisioning(record) => {
            Ok((record.operation_id.clone(), record.owned_entry.clone()))
        }
        ArchProvisionState::Ready(entry) => Ok((String::new(), entry.clone())),
        ArchProvisionState::Uninstalling(record) => {
            Ok((record.operation_id.clone(), record.owned_entry.clone()))
        }
        ArchProvisionState::Unprovisioned | ArchProvisionState::Uninstalled(_) => {
            Err(Error::NotConfigured)
        }
    }
}

fn same_owned_identity(left: &OwnedArchEntry, right: &OwnedArchEntry) -> bool {
    left.boot_id == right.boot_id
        && left.identity == right.identity
        && left.identity_version == right.identity_version
        && left.uki_path == right.uki_path
        && left.build == right.build
}

fn is_attempted_step(state: &ArchProvisionState) -> bool {
    matches!(
        state,
        ArchProvisionState::Provisioning(ProvisioningRecord {
            step: ProvisioningStep::UkiPublicationAttempted
                | ProvisioningStep::BootEntryCreateAttempted
                | ProvisioningStep::BootOrderAppendAttempted,
            ..
        }) | ArchProvisionState::Uninstalling(UninstallingRecord {
            step: UninstallingStep::BootOrderRemovalAttempted
                | UninstallingStep::BootEntryRemovalAttempted
                | UninstallingStep::UkiRemovalAttempted,
            ..
        })
    )
}

fn is_verified_step(state: &ArchProvisionState) -> bool {
    matches!(
        state,
        ArchProvisionState::Provisioning(ProvisioningRecord {
            step: ProvisioningStep::UkiPublished
                | ProvisioningStep::BootEntryReadBackVerified
                | ProvisioningStep::BootOrderReadBackVerified,
            ..
        }) | ArchProvisionState::Uninstalling(UninstallingRecord {
            step: UninstallingStep::BootOrderRemoved
                | UninstallingStep::BootOrderRemovalReadBackVerified
                | UninstallingStep::BootEntryRemoved
                | UninstallingStep::BootEntryRemovalReadBackVerified
                | UninstallingStep::UkiRemoved,
            ..
        })
    )
}

fn valid_proof_transition(prior: &ArchProvisionState, next: &ArchProvisionState) -> bool {
    use ProvisioningStep as P;
    use UninstallingStep as U;
    match (prior, next) {
        (ArchProvisionState::Provisioning(a), ArchProvisionState::Provisioning(b))
            if a.operation_id == b.operation_id
                && same_owned_identity(&a.owned_entry, &b.owned_entry) =>
        {
            matches!(
                (a.step, b.step),
                (P::UkiPublicationPending, P::UkiPublicationAttempted)
                    | (P::UkiPublicationAttempted, P::UkiPublished)
                    | (P::UkiPublished, P::BootEntryCreateAttempted)
                    | (P::BootEntryCreateAttempted, P::BootEntryReadBackVerified)
                    | (P::BootEntryCreateAttempted, P::BootEntryCreated)
                    | (P::BootEntryCreated, P::BootEntryReadBackVerified)
                    | (P::BootEntryReadBackVerified, P::BootOrderAppendAttempted)
                    | (P::BootOrderAppendAttempted, P::BootOrderReadBackVerified)
                    | (P::BootOrderAppendAttempted, P::BootOrderAppended)
                    | (P::BootOrderAppended, P::BootOrderReadBackVerified),
            )
        }
        (ArchProvisionState::Uninstalling(a), ArchProvisionState::Uninstalling(b))
            if a.operation_id == b.operation_id && a.owned_entry == b.owned_entry =>
        {
            matches!(
                (a.step, b.step),
                (U::Started, U::BootOrderRemovalAttempted)
                    | (U::BootOrderRemovalAttempted, U::BootOrderRemoved)
                    | (
                        U::BootOrderRemovalAttempted,
                        U::BootOrderRemovalReadBackVerified
                    )
                    | (U::BootOrderRemoved, U::BootOrderRemovalReadBackVerified)
                    | (
                        U::BootOrderRemovalReadBackVerified,
                        U::BootEntryRemovalAttempted
                    )
                    | (U::BootEntryRemovalAttempted, U::BootEntryRemoved)
                    | (
                        U::BootEntryRemovalAttempted,
                        U::BootEntryRemovalReadBackVerified
                    )
                    | (U::BootEntryRemoved, U::BootEntryRemovalReadBackVerified)
                    | (U::BootEntryRemovalReadBackVerified, U::UkiRemovalAttempted)
                    | (U::UkiRemovalAttempted, U::UkiRemoved),
            )
        }
        (ArchProvisionState::Provisioning(a), ArchProvisionState::Ready(entry))
            if a.step == P::BootOrderReadBackVerified
                && a.residual.is_empty()
                && a.owned_entry == *entry =>
        {
            true
        }
        _ => false,
    }
}

/// Run a complete explicit provision while holding the store's exclusive operation lock.
pub fn provision<F: Filesystem, B: LifecycleBackend>(
    store: &mut ArchProvisionStore<F>,
    backend: &mut B,
    intent: ProvisionIntent,
) -> Result<ArchProvisionState, Error> {
    if intent.operation_id.is_empty()
        || intent.operation_id.len() > 128
        || intent.operation_id.chars().any(char::is_control)
        || intent.owned_entry.publish.is_some()
    {
        return Err(Error::CorruptRecord);
    }
    let current = store.load()?;
    if !matches!(
        current,
        ArchProvisionState::Unprovisioned | ArchProvisionState::Uninstalled(_)
    ) {
        return Err(Error::NotConfigured);
    }
    let pending = ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: intent.operation_id,
        operation_version: 1,
        owned_entry: intent.owned_entry,
        step: ProvisioningStep::UkiPublicationPending,
        residual: Vec::new(),
    });
    store.save(&pending)?;

    let ArchProvisionState::Provisioning(record) = &pending else {
        unreachable!()
    };
    let (metadata, observed) = backend.prepare_uki_publication(&record.owned_entry)?;
    require_readback(&observed, &LifecycleReadback::UkiAbsent)?;
    let attempt = provisioning_step(
        &pending,
        ProvisioningStep::UkiPublicationAttempted,
        Some(metadata.clone()),
    )?;
    commit(
        store,
        pending.clone(),
        attempt.clone(),
        ProofBinding::Uki(metadata.clone()),
        ProofBinding::UkiAbsent,
    )?;
    let observed = match backend.publish_uki(&record.owned_entry, &metadata) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback(&observed, &LifecycleReadback::UkiPresent(metadata.clone()))?;
    let published = provisioning_step(&attempt, ProvisioningStep::UkiPublished, Some(metadata))?;
    commit(
        store,
        attempt,
        published.clone(),
        ProofBinding::Uki(published_publish(&published)?),
        ProofBinding::Uki(published_publish(&published)?),
    )?;

    let entry = owned_entry(&published)?;
    let observed = backend.prepare_boot_entry(entry)?;
    require_readback(&observed, &LifecycleReadback::BootEntryAbsent)?;
    let attempt = provisioning_step(
        &published,
        ProvisioningStep::BootEntryCreateAttempted,
        published_publish_opt(&published)?,
    )?;
    commit(
        store,
        published.clone(),
        attempt.clone(),
        ProofBinding::BootEntryPresent,
        ProofBinding::BootEntryAbsent,
    )?;
    let observed = match backend.create_boot_entry(entry) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback(&observed, &LifecycleReadback::BootEntryPresent)?;
    let verified = provisioning_step(
        &attempt,
        ProvisioningStep::BootEntryReadBackVerified,
        published_publish_opt(&attempt)?,
    )?;
    commit(
        store,
        attempt,
        verified.clone(),
        ProofBinding::BootEntryPresent,
        ProofBinding::BootEntryPresent,
    )?;

    let entry = owned_entry(&verified)?;
    let observed = backend.prepare_boot_order_append(entry)?;
    require_readback(&observed, &LifecycleReadback::BootOrderAbsent)?;
    let attempt = provisioning_step(
        &verified,
        ProvisioningStep::BootOrderAppendAttempted,
        published_publish_opt(&verified)?,
    )?;
    commit(
        store,
        verified.clone(),
        attempt.clone(),
        ProofBinding::BootOrderContains,
        ProofBinding::BootOrderAbsent,
    )?;
    let observed = match backend.append_boot_order(entry) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback(&observed, &LifecycleReadback::BootOrderContains)?;
    let verified = provisioning_step(
        &attempt,
        ProvisioningStep::BootOrderReadBackVerified,
        published_publish_opt(&attempt)?,
    )?;
    commit(
        store,
        attempt,
        verified.clone(),
        ProofBinding::BootOrderContains,
        ProofBinding::BootOrderContains,
    )?;
    let ready = ArchProvisionState::Ready(owned_entry(&verified)?.clone());
    commit(
        store,
        verified,
        ready.clone(),
        ProofBinding::BootOrderContains,
        ProofBinding::BootOrderContains,
    )?;
    Ok(ready)
}

/// Run complete cleanup for the exact currently journal-owned entry.
pub fn uninstall<F: Filesystem, B: LifecycleBackend>(
    store: &mut ArchProvisionStore<F>,
    backend: &mut B,
    operation_id: String,
) -> Result<ArchProvisionState, Error> {
    let current = store.load()?;
    let ArchProvisionState::Ready(entry) = current.clone() else {
        return Err(Error::NotConfigured);
    };
    let started = super::boot_order::begin_uninstall(entry.clone(), operation_id)?;
    store.save(&started)?;

    let observed = backend.prepare_boot_order_remove(&entry)?;
    require_readback(&observed, &LifecycleReadback::BootOrderContains)?;
    let attempt = uninstall_step(&started, UninstallingStep::BootOrderRemovalAttempted)?;
    commit(
        store,
        started.clone(),
        attempt.clone(),
        ProofBinding::BootOrderAbsent,
        ProofBinding::BootOrderContains,
    )?;
    let observed = match backend.remove_boot_order(&entry) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback(&observed, &LifecycleReadback::BootOrderAbsent)?;
    let removed = uninstall_step(&attempt, UninstallingStep::BootOrderRemoved)?;
    commit(
        store,
        attempt,
        removed.clone(),
        ProofBinding::BootOrderAbsent,
        ProofBinding::BootOrderAbsent,
    )?;
    let verified = uninstall_step(&removed, UninstallingStep::BootOrderRemovalReadBackVerified)?;
    commit(
        store,
        removed,
        verified.clone(),
        ProofBinding::BootOrderAbsent,
        ProofBinding::BootOrderAbsent,
    )?;

    let observed = backend.prepare_boot_entry_remove(&entry)?;
    require_readback(&observed, &LifecycleReadback::BootEntryPresent)?;
    let attempt = uninstall_step(&verified, UninstallingStep::BootEntryRemovalAttempted)?;
    commit(
        store,
        verified,
        attempt.clone(),
        ProofBinding::BootEntryAbsent,
        ProofBinding::BootEntryPresent,
    )?;
    let observed = match backend.remove_boot_entry(&entry) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback(&observed, &LifecycleReadback::BootEntryAbsent)?;
    let removed = uninstall_step(&attempt, UninstallingStep::BootEntryRemoved)?;
    commit(
        store,
        attempt,
        removed.clone(),
        ProofBinding::BootEntryAbsent,
        ProofBinding::BootEntryAbsent,
    )?;
    let verified = uninstall_step(&removed, UninstallingStep::BootEntryRemovalReadBackVerified)?;
    commit(
        store,
        removed,
        verified.clone(),
        ProofBinding::BootEntryAbsent,
        ProofBinding::BootEntryAbsent,
    )?;

    let observed = backend.prepare_uki_remove(&entry)?;
    let expected_uki = entry.publish.clone().ok_or(Error::CorruptRecord)?;
    require_readback(
        &observed,
        &LifecycleReadback::UkiPresent(expected_uki.clone()),
    )?;
    let attempt = uninstall_step(&verified, UninstallingStep::UkiRemovalAttempted)?;
    commit(
        store,
        verified,
        attempt.clone(),
        ProofBinding::UkiAbsent,
        ProofBinding::Uki(expected_uki.clone()),
    )?;
    let observed = match backend.remove_uki(&entry) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback(&observed, &LifecycleReadback::UkiAbsent)?;
    let removed = uninstall_step(&attempt, UninstallingStep::UkiRemoved)?;
    commit(
        store,
        attempt,
        removed.clone(),
        ProofBinding::UkiAbsent,
        ProofBinding::UkiAbsent,
    )?;
    store.complete_uninstall(&removed)?;
    store.load()
}

/// Reconcile a persisted attempted checkpoint without advancing it or repeating a mutation.
pub fn recover<F: Filesystem, B: LifecycleBackend>(
    store: &mut ArchProvisionStore<F>,
    backend: &mut B,
) -> Result<ArchProvisionState, Error> {
    let state = store.load()?;
    if !is_attempted_step(&state) {
        return Ok(state);
    }
    let observed = backend.observe(&state);
    let residual = match (&state, observed) {
        (ArchProvisionState::Provisioning(record), Ok(readback)) => match record.step {
            ProvisioningStep::UkiPublicationAttempted
                if !matches!(readback, LifecycleReadback::UkiPresent(_)) =>
            {
                Some(Residual::UkiMayRemain)
            }
            ProvisioningStep::BootEntryCreateAttempted
                if matches!(readback, LifecycleReadback::BootEntryPresent) =>
            {
                Some(Residual::BootEntryMayExist)
            }
            ProvisioningStep::BootOrderAppendAttempted
                if matches!(readback, LifecycleReadback::BootOrderContains) =>
            {
                Some(Residual::BootOrderMayContainEntry)
            }
            _ => None,
        },
        (ArchProvisionState::Uninstalling(record), Ok(readback)) => match record.step {
            UninstallingStep::BootOrderRemovalAttempted
                if matches!(readback, LifecycleReadback::BootOrderContains) =>
            {
                Some(Residual::BootOrderMayContainEntry)
            }
            UninstallingStep::BootEntryRemovalAttempted
                if matches!(readback, LifecycleReadback::BootEntryPresent) =>
            {
                Some(Residual::BootEntryMayExist)
            }
            UninstallingStep::UkiRemovalAttempted
                if !matches!(readback, LifecycleReadback::UkiAbsent) =>
            {
                Some(Residual::UkiMayRemain)
            }
            _ => None,
        },
        (_, Err(_)) => Some(Residual::ConfigurationMayRemain),
        _ => None,
    };
    if let Some(residual) = residual {
        let mut retained = state.clone();
        add_residual(&mut retained, residual)?;
        store.save(&retained)?;
    }
    store.load()
}

fn commit<F: Filesystem>(
    store: &mut ArchProvisionStore<F>,
    prior: ArchProvisionState,
    next: ArchProvisionState,
    expected: ProofBinding,
    observed: ProofBinding,
) -> Result<(), Error> {
    let proof = LifecycleProof::new(prior, next, expected, observed)?;
    store.commit_proof(&proof)
}

fn fail_at<F: Filesystem>(
    store: &mut ArchProvisionStore<F>,
    attempt: &ArchProvisionState,
    failure: LifecycleFailure,
) -> Result<ArchProvisionState, Error> {
    if let LifecycleFailure::Uncertain { residual, .. } = failure {
        let mut retained = attempt.clone();
        add_residual(&mut retained, residual)?;
        store.save(&retained)?;
    }
    Err(failure.error())
}

fn add_residual(state: &mut ArchProvisionState, residual: Residual) -> Result<(), Error> {
    let list = match state {
        ArchProvisionState::Provisioning(record) => &mut record.residual,
        ArchProvisionState::Uninstalling(record) => &mut record.residual,
        _ => return Err(Error::NotConfigured),
    };
    if !list.contains(&residual) {
        list.push(residual);
    }
    Ok(())
}

fn require_readback(actual: &LifecycleReadback, expected: &LifecycleReadback) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::ReadbackFailed)
    }
}

fn owned_entry(state: &ArchProvisionState) -> Result<&OwnedArchEntry, Error> {
    match state {
        ArchProvisionState::Provisioning(record) => Ok(&record.owned_entry),
        _ => Err(Error::NotConfigured),
    }
}

fn published_publish(state: &ArchProvisionState) -> Result<PublishMetadata, Error> {
    published_publish_opt(state)?.ok_or(Error::CorruptRecord)
}

fn published_publish_opt(state: &ArchProvisionState) -> Result<Option<PublishMetadata>, Error> {
    Ok(owned_entry(state)?.publish.clone())
}

fn provisioning_step(
    state: &ArchProvisionState,
    step: ProvisioningStep,
    publish: Option<PublishMetadata>,
) -> Result<ArchProvisionState, Error> {
    let ArchProvisionState::Provisioning(record) = state else {
        return Err(Error::NotConfigured);
    };
    Ok(ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: record.operation_id.clone(),
        operation_version: record.operation_version,
        owned_entry: OwnedArchEntry {
            publish,
            ..record.owned_entry.clone()
        },
        step,
        residual: record.residual.clone(),
    }))
}

fn uninstall_step(
    state: &ArchProvisionState,
    step: UninstallingStep,
) -> Result<ArchProvisionState, Error> {
    let ArchProvisionState::Uninstalling(record) = state else {
        return Err(Error::NotConfigured);
    };
    Ok(ArchProvisionState::Uninstalling(UninstallingRecord {
        operation_id: record.operation_id.clone(),
        operation_version: record.operation_version,
        owned_entry: record.owned_entry.clone(),
        step,
        residual: record.residual.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boothop_core::{
        BootId, BuildMetadata, CanonicalDevicePathNode, CanonicalEndEntireNode,
        CanonicalFilePathNode, CanonicalHardDriveNode, CanonicalIdentity, OpaqueAlgorithm,
        OpaqueExactV1,
    };

    fn entry() -> OwnedArchEntry {
        OwnedArchEntry {
            boot_id: BootId(7),
            identity: CanonicalIdentity {
                file_path_list_length: 0,
                nodes: [
                    CanonicalDevicePathNode::HardDrive(CanonicalHardDriveNode {
                        node_type: 4,
                        subtype: 1,
                        length: 42,
                        partition_number: 1,
                        partition_start_lba: 1,
                        partition_size_lba: 2,
                        partition_signature_uefi_bytes: [0; 16],
                        mbr_type: 2,
                        signature_type: 2,
                    }),
                    CanonicalDevicePathNode::FilePath(CanonicalFilePathNode {
                        node_type: 4,
                        subtype: 4,
                        length: 4,
                        path_utf16: Vec::new(),
                        terminator: 0,
                    }),
                    CanonicalDevicePathNode::EndEntire(CanonicalEndEntireNode {
                        node_type: 127,
                        subtype: 255,
                        length: 4,
                    }),
                ],
                optional_data: OpaqueExactV1 {
                    algorithm: OpaqueAlgorithm::Sha256,
                    byte_length: 0,
                    digest: [0; 32],
                },
            },
            identity_version: 1,
            uki_path: "EFI/BootHop/arch.efi".into(),
            build: BuildMetadata {
                kernel: "k".into(),
                kernel_release: "r".into(),
                initramfs_sha256: [0; 32],
            },
            publish: Some(PublishMetadata {
                sha256: [1; 32],
                size: 1,
            }),
        }
    }

    fn verified_state(operation_id: &str) -> ArchProvisionState {
        ArchProvisionState::Provisioning(ProvisioningRecord {
            operation_id: operation_id.into(),
            operation_version: 1,
            owned_entry: entry(),
            step: ProvisioningStep::UkiPublished,
            residual: Vec::new(),
        })
    }

    #[test]
    fn proofs_reject_stale_operation_and_mismatched_readback() {
        let prior = verified_state("op-1");
        let mut next = provisioning_step(
            &prior,
            ProvisioningStep::BootEntryCreateAttempted,
            Some(PublishMetadata {
                sha256: [1; 32],
                size: 1,
            }),
        )
        .unwrap();
        if let ArchProvisionState::Provisioning(record) = &mut next {
            record.operation_id = "op-2".into();
        }
        let stale = LifecycleProof::new(
            prior.clone(),
            next,
            ProofBinding::BootEntryPresent,
            ProofBinding::BootEntryAbsent,
        )
        .unwrap();
        assert_eq!(stale.validate(&prior), Err(Error::IdentityMismatch));

        let mut advanced = provisioning_step(
            &prior,
            ProvisioningStep::BootEntryReadBackVerified,
            Some(PublishMetadata {
                sha256: [1; 32],
                size: 1,
            }),
        )
        .unwrap();
        if let ArchProvisionState::Provisioning(record) = &mut advanced {
            record.operation_id = "op-1".into();
        }
        let mismatched = LifecycleProof::new(
            prior.clone(),
            advanced,
            ProofBinding::BootEntryPresent,
            ProofBinding::BootEntryAbsent,
        )
        .unwrap();
        assert_eq!(mismatched.validate(&prior), Err(Error::ReadbackFailed));
        assert_eq!(
            mismatched.validate(&verified_state("op-1")),
            Err(Error::ReadbackFailed)
        );
    }
}
