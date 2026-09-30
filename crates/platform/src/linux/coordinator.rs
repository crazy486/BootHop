//! Trusted Arch provisioning and uninstall coordination.
//!
//! This is deliberately a small, injected boundary.  The coordinator owns the journal guard
//! for the complete operation and only accepts postconditions returned by a trusted backend.
//! No implementation in this module opens firmware, an ESP, or a system configuration file.

use super::arch_provision_store::ArchProvisionStore;
use super::boot_order::BootOrderValue;
use super::store::Filesystem;
use boothop_core::{
    ArchProvisionState, Error, OwnedArchEntry, ProvisioningRecord, ProvisioningStep,
    PublishMetadata, Residual, UninstallingRecord, UninstallingStep,
};
use std::marker::PhantomData;

/// A readback supplied by a trusted, narrowly scoped lifecycle adapter.
///
/// The enum intentionally carries no path, raw EFI bytes, or caller-selected Boot ID.  The
/// owned identity is taken only from the journal state held by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleReadback {
    UkiAbsent,
    UkiPresent(PublishMetadata),
    BootEntryAbsent,
    BootEntryPresent(boothop_core::CanonicalIdentity),
    BootOrder(BootOrderValue),
    /// Ownership of the exact Boot#### bytes and the full BootOrder snapshot observed together
    /// before an order mutation is authorized.
    BootEntryAndOrder {
        identity: boothop_core::CanonicalIdentity,
        order: BootOrderValue,
    },
}

/// A mutation failure says whether the mutation was rejected before its write boundary or may
/// have crossed it.  Possible partial mutations are retained at the attempted checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleFailure {
    Rejected(Error),
    /// The adapter stopped before its mutation boundary because the observed resource no
    /// longer matched the committed proof. Keep the residual even though this call did not
    /// write, so a stale Attempted checkpoint cannot be mistaken for a clean retry point.
    Stopped {
        error: Error,
        residual: Residual,
    },
    Uncertain {
        error: Error,
        residual: Residual,
    },
}

impl LifecycleFailure {
    pub fn rejected(error: Error) -> Self {
        Self::Rejected(error)
    }

    pub fn stopped(error: Error, residual: Residual) -> Self {
        Self::Stopped { error, residual }
    }

    pub fn uncertain(error: Error, residual: Residual) -> Self {
        Self::Uncertain { error, residual }
    }

    fn error(&self) -> Error {
        match self {
            Self::Rejected(error) | Self::Stopped { error, .. } | Self::Uncertain { error, .. } => {
                error.clone()
            }
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
/// exact readback needed to establish the pre-mutation proof. Each mutation method consumes an
/// action-specific permit containing the committed Attempted checkpoint and its proof evidence.
/// It performs one write/delete at most, returns an exact readback, and never retries or rolls back.
pub trait LifecycleBackend {
    fn prepare_uki_publication(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<(PublishMetadata, LifecycleReadback), Error>;
    fn publish_uki(
        &mut self,
        permit: UkiPublishPermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_boot_entry(&mut self, entry: &OwnedArchEntry) -> Result<LifecycleReadback, Error>;
    fn create_boot_entry(
        &mut self,
        permit: BootEntryCreatePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_boot_order_append(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error>;
    /// Recheck the exact Boot#### identity immediately before invoking the order writer.
    fn append_boot_order(
        &mut self,
        permit: BootOrderAppendPermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_boot_order_remove(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error>;
    /// Recheck the exact Boot#### identity immediately before invoking the order writer.
    fn remove_boot_order(
        &mut self,
        permit: BootOrderRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_boot_entry_remove(
        &mut self,
        entry: &OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error>;
    fn remove_boot_entry(
        &mut self,
        permit: BootEntryRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    fn prepare_uki_remove(&mut self, entry: &OwnedArchEntry) -> Result<LifecycleReadback, Error>;
    fn remove_uki(
        &mut self,
        permit: UkiRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure>;

    /// Restart reconciliation is read-only.  It must not call any mutation method.
    fn observe(&mut self, state: &ArchProvisionState) -> Result<LifecycleReadback, Error>;

    /// Restart reconciliation also confirms that the fixed UKI still has the journaled
    /// identity/hash/size before an attempted Boot#### or BootOrder checkpoint is interpreted.
    fn observe_uki_ownership(&mut self, entry: &OwnedArchEntry)
    -> Result<LifecycleReadback, Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Exact precondition or expected postcondition evidence bound to a lifecycle proof.
pub enum LifecycleProofBinding {
    UkiAbsent,
    Uki(PublishMetadata),
    BootEntryAbsent,
    BootEntryPresent,
    BootOrderBefore(BootOrderValue),
    BootEntryAndOrderBefore {
        identity: boothop_core::CanonicalIdentity,
        order: BootOrderValue,
    },
    BootOrderTransition {
        before: BootOrderValue,
        after: BootOrderValue,
    },
}

/// Private proof object.  Its fields and constructor are crate-private; callers can only obtain
/// one through coordinator code after an exact prepare/readback comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleProof {
    prior: ArchProvisionState,
    next: ArchProvisionState,
    operation_id: String,
    owned_entry: OwnedArchEntry,
    expected: LifecycleProofBinding,
    observed: LifecycleProofBinding,
}

impl LifecycleProof {
    fn new(
        prior: ArchProvisionState,
        next: ArchProvisionState,
        expected: LifecycleProofBinding,
        observed: LifecycleProofBinding,
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
        if !proof_bindings_valid(&self.next, &self.expected, &self.observed) {
            return Err(Error::ReadbackFailed);
        }
        if !valid_proof_transition(&self.prior, &self.next) {
            return Err(Error::NotConfigured);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationAction {
    UkiPublish,
    BootEntryCreate,
    BootOrderAppend,
    BootOrderRemove,
    BootEntryRemove,
    UkiRemove,
}

struct MutationPermitBinding {
    action: MutationAction,
    operation_id: String,
    operation_version: u64,
    owned_entry: OwnedArchEntry,
}

impl MutationPermitBinding {
    fn validate(proof: &LifecycleProof, expected_action: MutationAction) -> Result<Self, Error> {
        proof.validate(&proof.prior)?;
        if mutation_action(&proof.next) != Some(expected_action) {
            return Err(Error::NotConfigured);
        }
        let (operation_id, owned_entry) = operation_and_entry(&proof.next)?;
        let committed_version = operation_version(&proof.next)?;
        if operation_id != proof.operation_id
            || !same_owned_identity(&owned_entry, &proof.owned_entry)
            || operation_version(&proof.prior)? != committed_version
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(Self {
            action: expected_action,
            operation_id,
            operation_version: committed_version,
            owned_entry,
        })
    }
}

struct MutationPermitEvidence {
    proof: LifecycleProof,
    binding: MutationPermitBinding,
}

impl MutationPermitEvidence {
    fn from_committed_proof(proof: LifecycleProof, binding: MutationPermitBinding) -> Self {
        Self { proof, binding }
    }

    fn operation_id(&self) -> &str {
        &self.binding.operation_id
    }

    fn operation_version(&self) -> u64 {
        self.binding.operation_version
    }

    fn owned_entry(&self) -> &OwnedArchEntry {
        &self.binding.owned_entry
    }

    fn attempted_state(&self) -> &ArchProvisionState {
        &self.proof.next
    }

    fn expected_evidence(&self) -> &LifecycleProofBinding {
        &self.proof.expected
    }

    fn precondition_evidence(&self) -> &LifecycleProofBinding {
        &self.proof.observed
    }
}

macro_rules! define_lifecycle_permit {
    ($name:ident, $action:ident) => {
        /// Opaque authority for exactly one committed Arch lifecycle mutation.
        ///
        /// The coordinator is the only constructor. The permit borrows the operation store
        /// mutably until the matching mutation method consumes it.
        #[must_use = "a lifecycle permit must be consumed by its matching backend mutation"]
        pub struct $name<'store> {
            evidence: MutationPermitEvidence,
            _store_borrow: PhantomData<&'store mut ()>,
        }

        impl<'store> $name<'store> {
            fn from_committed_proof(proof: LifecycleProof, binding: MutationPermitBinding) -> Self {
                debug_assert_eq!(binding.action, MutationAction::$action);
                let evidence = MutationPermitEvidence::from_committed_proof(proof, binding);
                Self {
                    evidence,
                    _store_borrow: PhantomData,
                }
            }

            /// Operation identity journaled for the committed Attempted checkpoint.
            pub fn operation_id(&self) -> &str {
                self.evidence.operation_id()
            }

            /// Journal operation version bound to the committed Attempted checkpoint.
            pub fn operation_version(&self) -> u64 {
                self.evidence.operation_version()
            }

            /// Full owned entry recorded in the committed Attempted checkpoint.
            pub fn owned_entry(&self) -> &OwnedArchEntry {
                self.evidence.owned_entry()
            }

            /// Exact checkpoint committed before this permit was issued.
            pub fn attempted_state(&self) -> &ArchProvisionState {
                self.evidence.attempted_state()
            }

            /// Expected postcondition encoded by the coordinator's lifecycle proof.
            pub fn expected_evidence(&self) -> &LifecycleProofBinding {
                self.evidence.expected_evidence()
            }

            /// Exact precondition evidence observed before the Attempted commit.
            pub fn precondition_evidence(&self) -> &LifecycleProofBinding {
                self.evidence.precondition_evidence()
            }
        }
    };
}

define_lifecycle_permit!(UkiPublishPermit, UkiPublish);
define_lifecycle_permit!(BootEntryCreatePermit, BootEntryCreate);
define_lifecycle_permit!(BootOrderAppendPermit, BootOrderAppend);
define_lifecycle_permit!(BootOrderRemovePermit, BootOrderRemove);
define_lifecycle_permit!(BootEntryRemovePermit, BootEntryRemove);
define_lifecycle_permit!(UkiRemovePermit, UkiRemove);

fn operation_version(state: &ArchProvisionState) -> Result<u64, Error> {
    match state {
        ArchProvisionState::Provisioning(record) => Ok(record.operation_version),
        ArchProvisionState::Uninstalling(record) => Ok(record.operation_version),
        ArchProvisionState::Unprovisioned
        | ArchProvisionState::Ready(_)
        | ArchProvisionState::Uninstalled(_) => Err(Error::NotConfigured),
    }
}

fn mutation_action(state: &ArchProvisionState) -> Option<MutationAction> {
    match state {
        ArchProvisionState::Provisioning(record) => match record.step {
            ProvisioningStep::UkiPublicationAttempted => Some(MutationAction::UkiPublish),
            ProvisioningStep::BootEntryCreateAttempted => Some(MutationAction::BootEntryCreate),
            ProvisioningStep::BootOrderAppendAttempted => Some(MutationAction::BootOrderAppend),
            ProvisioningStep::UkiPublicationPending
            | ProvisioningStep::UkiPublished
            | ProvisioningStep::BootEntryCreated
            | ProvisioningStep::BootEntryReadBackVerified
            | ProvisioningStep::BootOrderAppendWriteCompleted
            | ProvisioningStep::BootOrderAppended
            | ProvisioningStep::BootOrderReadBackVerified => None,
        },
        ArchProvisionState::Uninstalling(record) => match record.step {
            UninstallingStep::BootOrderRemovalAttempted => Some(MutationAction::BootOrderRemove),
            UninstallingStep::BootEntryRemovalAttempted => Some(MutationAction::BootEntryRemove),
            UninstallingStep::UkiRemovalAttempted => Some(MutationAction::UkiRemove),
            UninstallingStep::Started
            | UninstallingStep::BootOrderRemovalWriteCompleted
            | UninstallingStep::BootOrderRemoved
            | UninstallingStep::BootOrderRemovalReadBackVerified
            | UninstallingStep::BootEntryDeleteCompleted
            | UninstallingStep::BootEntryRemoved
            | UninstallingStep::BootEntryRemovalReadBackVerified
            | UninstallingStep::UkiDeleteCompleted
            | UninstallingStep::UkiRemoved => None,
        },
        ArchProvisionState::Unprovisioned
        | ArchProvisionState::Ready(_)
        | ArchProvisionState::Uninstalled(_) => None,
    }
}

fn proof_bindings_valid(
    state: &ArchProvisionState,
    expected: &LifecycleProofBinding,
    observed: &LifecycleProofBinding,
) -> bool {
    let same = expected == observed;
    match state {
        ArchProvisionState::Provisioning(record) => match record.step {
            ProvisioningStep::UkiPublicationAttempted => {
                matches!(expected, LifecycleProofBinding::Uki(metadata) if record.owned_entry.publish.as_ref() == Some(metadata))
                    && matches!(observed, LifecycleProofBinding::UkiAbsent)
            }
            ProvisioningStep::UkiPublished => {
                matches!(expected, LifecycleProofBinding::Uki(metadata) if record.owned_entry.publish.as_ref() == Some(metadata))
                    && same
            }
            ProvisioningStep::BootEntryCreateAttempted => {
                matches!(expected, LifecycleProofBinding::BootEntryPresent)
                    && matches!(observed, LifecycleProofBinding::BootEntryAbsent)
            }
            ProvisioningStep::BootEntryCreated | ProvisioningStep::BootEntryReadBackVerified => {
                matches!(expected, LifecycleProofBinding::BootEntryPresent) && same
            }
            ProvisioningStep::BootOrderAppendAttempted => {
                matches!(
                    (expected, observed),
                    (
                        LifecycleProofBinding::BootEntryAndOrderBefore { identity, order },
                        LifecycleProofBinding::BootEntryAndOrderBefore {
                            identity: observed_identity,
                            order: observed_order,
                        },
                    ) if identity == observed_identity
                        && identity == &record.owned_entry.identity
                        && order == observed_order
                        && boot_order_append_precondition(order, record.owned_entry.boot_id)
                )
            }
            ProvisioningStep::BootOrderAppended | ProvisioningStep::BootOrderReadBackVerified => {
                matches!(
                    (expected, observed),
                    (
                        LifecycleProofBinding::BootOrderTransition { before, after },
                        LifecycleProofBinding::BootOrderTransition {
                            before: observed_before,
                            after: observed_after,
                        },
                    ) if before == observed_before
                        && after == observed_after
                        && boot_order_append_transition(
                            before,
                            after,
                            record.owned_entry.boot_id,
                        )
                )
            }
            ProvisioningStep::BootOrderAppendWriteCompleted => same,
            ProvisioningStep::UkiPublicationPending => false,
        },
        ArchProvisionState::Uninstalling(record) => match record.step {
            UninstallingStep::BootOrderRemovalAttempted => {
                matches!(
                    (expected, observed),
                    (
                        LifecycleProofBinding::BootEntryAndOrderBefore { identity, order },
                        LifecycleProofBinding::BootEntryAndOrderBefore {
                            identity: observed_identity,
                            order: observed_order,
                        },
                    ) if identity == observed_identity
                        && identity == &record.owned_entry.identity
                        && order == observed_order
                        && boot_order_remove_precondition(order, record.owned_entry.boot_id)
                )
            }
            UninstallingStep::BootOrderRemoved
            | UninstallingStep::BootOrderRemovalReadBackVerified => {
                matches!(
                    (expected, observed),
                    (
                        LifecycleProofBinding::BootOrderTransition { before, after },
                        LifecycleProofBinding::BootOrderTransition {
                            before: observed_before,
                            after: observed_after,
                        },
                    ) if before == observed_before
                        && after == observed_after
                        && boot_order_remove_transition(
                            before,
                            after,
                            record.owned_entry.boot_id,
                        )
                )
            }
            UninstallingStep::BootEntryRemovalAttempted => {
                matches!(expected, LifecycleProofBinding::BootEntryAbsent)
                    && matches!(observed, LifecycleProofBinding::BootEntryPresent)
            }
            UninstallingStep::BootEntryRemoved
            | UninstallingStep::BootEntryRemovalReadBackVerified => {
                matches!(expected, LifecycleProofBinding::BootEntryAbsent) && same
            }
            UninstallingStep::UkiRemovalAttempted => {
                matches!(expected, LifecycleProofBinding::UkiAbsent)
                    && matches!(
                        observed,
                        LifecycleProofBinding::Uki(metadata)
                            if record.owned_entry.publish.as_ref() == Some(metadata)
                    )
            }
            UninstallingStep::UkiRemoved => {
                matches!(expected, LifecycleProofBinding::UkiAbsent) && same
            }
            UninstallingStep::Started
            | UninstallingStep::BootOrderRemovalWriteCompleted
            | UninstallingStep::BootEntryDeleteCompleted
            | UninstallingStep::UkiDeleteCompleted => same,
        },
        ArchProvisionState::Ready(entry) => matches!(
            (expected, observed),
            (
                LifecycleProofBinding::BootOrderTransition { before, after },
                LifecycleProofBinding::BootOrderTransition {
                    before: observed_before,
                    after: observed_after,
                },
            ) if before == observed_before
                && after == observed_after
                && boot_order_append_transition(before, after, entry.boot_id)
        ),
        ArchProvisionState::Unprovisioned | ArchProvisionState::Uninstalled(_) => false,
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

fn boot_order_append_precondition(before: &BootOrderValue, id: boothop_core::BootId) -> bool {
    before.validate().is_ok() && !before.ids.contains(&id)
}

fn boot_order_append_transition(
    before: &BootOrderValue,
    after: &BootOrderValue,
    id: boothop_core::BootId,
) -> bool {
    boot_order_append_precondition(before, id)
        && after.validate().is_ok()
        && before.appended(id).is_ok_and(|expected| expected == *after)
}

fn boot_order_remove_precondition(before: &BootOrderValue, id: boothop_core::BootId) -> bool {
    before.validate().is_ok() && before.ids.contains(&id)
}

fn boot_order_remove_transition(
    before: &BootOrderValue,
    after: &BootOrderValue,
    id: boothop_core::BootId,
) -> bool {
    boot_order_remove_precondition(before, id)
        && after.validate().is_ok()
        && before.without(id).is_ok_and(|expected| expected == *after)
}

fn entry_precondition_residual(error: &Error) -> Option<Residual> {
    matches!(error, Error::IdentityMismatch | Error::TargetMissing)
        .then_some(Residual::BootEntryMayExist)
}

fn is_nonterminal_state(state: &ArchProvisionState) -> bool {
    matches!(
        state,
        ArchProvisionState::Provisioning(_) | ArchProvisionState::Uninstalling(_)
    )
}

fn valid_proof_transition(prior: &ArchProvisionState, next: &ArchProvisionState) -> bool {
    use ProvisioningStep as P;
    use UninstallingStep as U;
    match (prior, next) {
        (ArchProvisionState::Provisioning(a), ArchProvisionState::Provisioning(b))
            if a.operation_id == b.operation_id
                && a.operation_version == b.operation_version
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
            if a.operation_id == b.operation_id
                && a.operation_version == b.operation_version
                && a.owned_entry == b.owned_entry =>
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
    let (metadata, observed) = match backend.prepare_uki_publication(&record.owned_entry) {
        Ok(value) => value,
        Err(error) => return fail_precondition(store, &pending, Residual::UkiMayRemain, error),
    };
    require_precondition_at(
        store,
        &pending,
        &observed,
        &LifecycleReadback::UkiAbsent,
        Residual::UkiMayRemain,
    )?;
    let attempt = provisioning_step(
        &pending,
        ProvisioningStep::UkiPublicationAttempted,
        Some(metadata.clone()),
    )?;
    let permit = commit_uki_publish_attempt(
        store,
        pending.clone(),
        attempt.clone(),
        LifecycleProofBinding::Uki(metadata.clone()),
        LifecycleProofBinding::UkiAbsent,
    )?;
    let observed = match backend.publish_uki(permit) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback_at(
        store,
        &attempt,
        &observed,
        &LifecycleReadback::UkiPresent(metadata.clone()),
        Residual::UkiMayRemain,
    )?;
    let published = provisioning_step(&attempt, ProvisioningStep::UkiPublished, Some(metadata))?;
    commit_after_mutation(
        store,
        &attempt,
        published.clone(),
        LifecycleProofBinding::Uki(published_publish(&published)?),
        LifecycleProofBinding::Uki(published_publish(&published)?),
        Residual::UkiMayRemain,
    )?;

    let entry = owned_entry(&published)?;
    let observed = match backend.prepare_boot_entry(entry) {
        Ok(observed) => observed,
        Err(error) => {
            return fail_precondition(store, &published, Residual::BootEntryMayExist, error);
        }
    };
    require_precondition_at(
        store,
        &published,
        &observed,
        &LifecycleReadback::BootEntryAbsent,
        Residual::BootEntryMayExist,
    )?;
    let attempt = provisioning_step(
        &published,
        ProvisioningStep::BootEntryCreateAttempted,
        published_publish_opt(&published)?,
    )?;
    let permit = commit_boot_entry_create_attempt(
        store,
        published.clone(),
        attempt.clone(),
        LifecycleProofBinding::BootEntryPresent,
        LifecycleProofBinding::BootEntryAbsent,
    )?;
    let observed = match backend.create_boot_entry(permit) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback_at(
        store,
        &attempt,
        &observed,
        &LifecycleReadback::BootEntryPresent(entry.identity.clone()),
        Residual::BootEntryMayExist,
    )?;
    let verified = provisioning_step(
        &attempt,
        ProvisioningStep::BootEntryReadBackVerified,
        published_publish_opt(&attempt)?,
    )?;
    commit_after_mutation(
        store,
        &attempt,
        verified.clone(),
        LifecycleProofBinding::BootEntryPresent,
        LifecycleProofBinding::BootEntryPresent,
        Residual::BootEntryMayExist,
    )?;

    let entry = owned_entry(&verified)?;
    let observed = match backend.prepare_boot_order_append(entry) {
        Ok(observed) => observed,
        Err(error) => {
            let residual =
                entry_precondition_residual(&error).unwrap_or(Residual::BootOrderMayContainEntry);
            return fail_precondition(store, &verified, residual, error);
        }
    };
    let (observed_identity, before) = match observed {
        LifecycleReadback::BootEntryAndOrder { identity, order }
            if identity == entry.identity
                && boot_order_append_precondition(&order, entry.boot_id) =>
        {
            (identity, order)
        }
        LifecycleReadback::BootEntryAndOrder { identity, .. } if identity != entry.identity => {
            return fail_precondition(
                store,
                &verified,
                Residual::BootEntryMayExist,
                Error::IdentityMismatch,
            );
        }
        _ => {
            return fail_precondition(
                store,
                &verified,
                Residual::BootOrderMayContainEntry,
                Error::ReadbackFailed,
            );
        }
    };
    let attempt = provisioning_step(
        &verified,
        ProvisioningStep::BootOrderAppendAttempted,
        published_publish_opt(&verified)?,
    )?;
    let order_proof = LifecycleProofBinding::BootEntryAndOrderBefore {
        identity: observed_identity,
        order: before.clone(),
    };
    let permit = commit_boot_order_append_attempt(
        store,
        verified.clone(),
        attempt.clone(),
        order_proof.clone(),
        order_proof,
    )?;
    let observed = match backend.append_boot_order(permit) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    let after = match observed {
        LifecycleReadback::BootOrder(after) => after,
        _ => {
            return fail_precondition(
                store,
                &attempt,
                Residual::BootOrderMayContainEntry,
                Error::ReadbackFailed,
            );
        }
    };
    let expected_after = match before.appended(entry.boot_id) {
        Ok(expected_after) => expected_after,
        Err(error) => {
            return fail_precondition(store, &attempt, Residual::BootOrderMayContainEntry, error);
        }
    };
    require_readback_at(
        store,
        &attempt,
        &LifecycleReadback::BootOrder(after.clone()),
        &LifecycleReadback::BootOrder(expected_after.clone()),
        Residual::BootOrderMayContainEntry,
    )?;
    let verified = provisioning_step(
        &attempt,
        ProvisioningStep::BootOrderReadBackVerified,
        published_publish_opt(&attempt)?,
    )?;
    let transition = LifecycleProofBinding::BootOrderTransition {
        before,
        after: expected_after,
    };
    commit_after_mutation(
        store,
        &attempt,
        verified.clone(),
        transition.clone(),
        transition.clone(),
        Residual::BootOrderMayContainEntry,
    )?;
    let ready = ArchProvisionState::Ready(owned_entry(&verified)?.clone());
    commit_preserving(
        store,
        &verified,
        ready.clone(),
        transition.clone(),
        transition,
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

    let observed = match backend.prepare_boot_order_remove(&entry) {
        Ok(observed) => observed,
        Err(error) => {
            let residual =
                entry_precondition_residual(&error).unwrap_or(Residual::BootOrderMayContainEntry);
            return fail_precondition(store, &started, residual, error);
        }
    };
    let (observed_identity, before) = match observed {
        LifecycleReadback::BootEntryAndOrder { identity, order }
            if identity == entry.identity
                && boot_order_remove_precondition(&order, entry.boot_id) =>
        {
            (identity, order)
        }
        LifecycleReadback::BootEntryAndOrder { identity, .. } if identity != entry.identity => {
            return fail_precondition(
                store,
                &started,
                Residual::BootEntryMayExist,
                Error::IdentityMismatch,
            );
        }
        _ => {
            return fail_precondition(
                store,
                &started,
                Residual::BootOrderMayContainEntry,
                Error::ReadbackFailed,
            );
        }
    };
    let attempt = uninstall_step(&started, UninstallingStep::BootOrderRemovalAttempted)?;
    let order_proof = LifecycleProofBinding::BootEntryAndOrderBefore {
        identity: observed_identity,
        order: before.clone(),
    };
    let permit = commit_boot_order_remove_attempt(
        store,
        started.clone(),
        attempt.clone(),
        order_proof.clone(),
        order_proof,
    )?;
    let observed = match backend.remove_boot_order(permit) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    let after = match observed {
        LifecycleReadback::BootOrder(after) => after,
        _ => {
            return fail_precondition(
                store,
                &attempt,
                Residual::BootOrderMayContainEntry,
                Error::ReadbackFailed,
            );
        }
    };
    let expected_after = match before.without(entry.boot_id) {
        Ok(expected_after) => expected_after,
        Err(error) => {
            return fail_precondition(store, &attempt, Residual::BootOrderMayContainEntry, error);
        }
    };
    require_readback_at(
        store,
        &attempt,
        &LifecycleReadback::BootOrder(after),
        &LifecycleReadback::BootOrder(expected_after.clone()),
        Residual::BootOrderMayContainEntry,
    )?;
    let removed = uninstall_step(&attempt, UninstallingStep::BootOrderRemoved)?;
    let transition = LifecycleProofBinding::BootOrderTransition {
        before,
        after: expected_after,
    };
    commit_after_mutation(
        store,
        &attempt,
        removed.clone(),
        transition.clone(),
        transition.clone(),
        Residual::BootOrderMayContainEntry,
    )?;
    let verified = uninstall_step(&removed, UninstallingStep::BootOrderRemovalReadBackVerified)?;
    commit_preserving(
        store,
        &removed,
        verified.clone(),
        transition.clone(),
        transition,
    )?;

    let observed = match backend.prepare_boot_entry_remove(&entry) {
        Ok(observed) => observed,
        Err(error) => {
            return fail_precondition(store, &verified, Residual::BootEntryMayExist, error);
        }
    };
    require_precondition_at(
        store,
        &verified,
        &observed,
        &LifecycleReadback::BootEntryPresent(entry.identity.clone()),
        Residual::BootEntryMayExist,
    )?;
    let attempt = uninstall_step(&verified, UninstallingStep::BootEntryRemovalAttempted)?;
    let permit = commit_boot_entry_remove_attempt(
        store,
        verified,
        attempt.clone(),
        LifecycleProofBinding::BootEntryAbsent,
        LifecycleProofBinding::BootEntryPresent,
    )?;
    let observed = match backend.remove_boot_entry(permit) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback_at(
        store,
        &attempt,
        &observed,
        &LifecycleReadback::BootEntryAbsent,
        Residual::BootEntryMayExist,
    )?;
    let removed = uninstall_step(&attempt, UninstallingStep::BootEntryRemoved)?;
    commit_after_mutation(
        store,
        &attempt,
        removed.clone(),
        LifecycleProofBinding::BootEntryAbsent,
        LifecycleProofBinding::BootEntryAbsent,
        Residual::BootEntryMayExist,
    )?;
    let verified = uninstall_step(&removed, UninstallingStep::BootEntryRemovalReadBackVerified)?;
    commit_preserving(
        store,
        &removed,
        verified.clone(),
        LifecycleProofBinding::BootEntryAbsent,
        LifecycleProofBinding::BootEntryAbsent,
    )?;

    let observed = match backend.prepare_uki_remove(&entry) {
        Ok(observed) => observed,
        Err(error) => return fail_precondition(store, &verified, Residual::UkiMayRemain, error),
    };
    let expected_uki = entry.publish.clone().ok_or(Error::CorruptRecord)?;
    require_precondition_at(
        store,
        &verified,
        &observed,
        &LifecycleReadback::UkiPresent(expected_uki.clone()),
        Residual::UkiMayRemain,
    )?;
    let attempt = uninstall_step(&verified, UninstallingStep::UkiRemovalAttempted)?;
    let permit = commit_uki_remove_attempt(
        store,
        verified,
        attempt.clone(),
        LifecycleProofBinding::UkiAbsent,
        LifecycleProofBinding::Uki(expected_uki.clone()),
    )?;
    let observed = match backend.remove_uki(permit) {
        Ok(observed) => observed,
        Err(failure) => return fail_at(store, &attempt, failure),
    };
    require_readback_at(
        store,
        &attempt,
        &observed,
        &LifecycleReadback::UkiAbsent,
        Residual::UkiMayRemain,
    )?;
    let removed = uninstall_step(&attempt, UninstallingStep::UkiRemoved)?;
    commit_after_mutation(
        store,
        &attempt,
        removed.clone(),
        LifecycleProofBinding::UkiAbsent,
        LifecycleProofBinding::UkiAbsent,
        Residual::UkiMayRemain,
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
    if !is_nonterminal_state(&state) {
        return Ok(state);
    }
    let mut retained = state.clone();
    let needs_uki_check = matches!(
        &state,
        ArchProvisionState::Provisioning(ProvisioningRecord {
            step: ProvisioningStep::UkiPublished
                | ProvisioningStep::BootEntryCreateAttempted
                | ProvisioningStep::BootEntryCreated
                | ProvisioningStep::BootEntryReadBackVerified
                | ProvisioningStep::BootOrderAppendAttempted
                | ProvisioningStep::BootOrderAppendWriteCompleted
                | ProvisioningStep::BootOrderAppended
                | ProvisioningStep::BootOrderReadBackVerified,
            ..
        }) | ArchProvisionState::Uninstalling(_)
    );
    if needs_uki_check {
        let entry = match &state {
            ArchProvisionState::Provisioning(record) => &record.owned_entry,
            ArchProvisionState::Uninstalling(record) => &record.owned_entry,
            _ => unreachable!(),
        };
        let uki = backend.observe_uki_ownership(entry);
        if !matches!(uki, Ok(ref readback) if uki_matches_recovery_checkpoint(&state, entry, readback))
        {
            add_residual(&mut retained, Residual::UkiMayRemain)?;
        }
    }

    match backend.observe(&state) {
        Ok(readback) => match &state {
            ArchProvisionState::Provisioning(record) => match record.step {
                ProvisioningStep::UkiPublicationPending
                | ProvisioningStep::UkiPublicationAttempted
                    if !matches!(readback, LifecycleReadback::UkiAbsent) =>
                {
                    add_residual(&mut retained, Residual::UkiMayRemain)?;
                }
                ProvisioningStep::UkiPublicationAttempted => {
                    add_residual(&mut retained, Residual::UkiMayRemain)?;
                }
                ProvisioningStep::UkiPublished if !uki_matches(&record.owned_entry, &readback) => {
                    add_residual(&mut retained, Residual::UkiMayRemain)?;
                }
                ProvisioningStep::BootEntryCreateAttempted => {
                    add_residual(&mut retained, Residual::BootEntryMayExist)?;
                }
                ProvisioningStep::BootEntryCreated
                | ProvisioningStep::BootEntryReadBackVerified
                    if !matches!(
                        readback,
                        LifecycleReadback::BootEntryPresent(ref identity)
                            if identity == &record.owned_entry.identity
                    ) =>
                {
                    add_residual(&mut retained, Residual::BootEntryMayExist)?;
                }
                ProvisioningStep::BootOrderAppendAttempted
                | ProvisioningStep::BootOrderAppendWriteCompleted
                | ProvisioningStep::BootOrderAppended
                | ProvisioningStep::BootOrderReadBackVerified => {
                    add_residual(&mut retained, Residual::BootOrderMayContainEntry)?;
                }
                _ => {}
            },
            ArchProvisionState::Uninstalling(record) => match record.step {
                UninstallingStep::Started
                    if !matches!(
                        readback,
                        LifecycleReadback::BootOrder(ref order)
                            if order.validate().is_ok()
                                && order.ids.contains(&record.owned_entry.boot_id)
                    ) =>
                {
                    add_residual(&mut retained, Residual::BootOrderMayContainEntry)?;
                }
                UninstallingStep::BootOrderRemovalAttempted
                | UninstallingStep::BootOrderRemovalWriteCompleted => {
                    add_residual(&mut retained, Residual::BootOrderMayContainEntry)?;
                }
                UninstallingStep::BootOrderRemoved
                | UninstallingStep::BootOrderRemovalReadBackVerified => {
                    // These checkpoints do not persist the exact full post-order.  Absence of
                    // the owned ID cannot prove that external entries were not reordered or
                    // removed after the prior readback, so restart reconciliation must retain
                    // a residual instead of inferring a clean BootOrder from partial evidence.
                    add_residual(&mut retained, Residual::BootOrderMayContainEntry)?;
                }
                UninstallingStep::BootEntryRemovalAttempted
                | UninstallingStep::BootEntryDeleteCompleted => {
                    add_residual(&mut retained, Residual::BootEntryMayExist)?;
                }
                UninstallingStep::BootEntryRemoved
                | UninstallingStep::BootEntryRemovalReadBackVerified
                    if !matches!(readback, LifecycleReadback::BootEntryAbsent) =>
                {
                    add_residual(&mut retained, Residual::BootEntryMayExist)?;
                }
                UninstallingStep::UkiRemovalAttempted | UninstallingStep::UkiDeleteCompleted => {
                    add_residual(&mut retained, Residual::UkiMayRemain)?;
                }
                UninstallingStep::UkiRemoved
                    if !matches!(readback, LifecycleReadback::UkiAbsent) =>
                {
                    add_residual(&mut retained, Residual::UkiMayRemain)?;
                }
                _ => {}
            },
            _ => {}
        },
        Err(_) => {
            if let Some(residual) = residual_for_state(&state) {
                add_residual(&mut retained, residual)?;
            }
        }
    }
    if retained != state {
        store.save(&retained)?;
    }
    store.load()
}

fn commit<F: Filesystem>(
    store: &mut ArchProvisionStore<F>,
    prior: ArchProvisionState,
    next: ArchProvisionState,
    expected: LifecycleProofBinding,
    observed: LifecycleProofBinding,
) -> Result<(), Error> {
    let proof = LifecycleProof::new(prior, next, expected, observed)?;
    store.commit_proof(&proof)
}

macro_rules! commit_mutation_attempt {
    ($function:ident, $permit:ident, $action:ident) => {
        fn $function<'store, F: Filesystem>(
            store: &'store mut ArchProvisionStore<F>,
            prior: ArchProvisionState,
            attempted: ArchProvisionState,
            expected: LifecycleProofBinding,
            observed: LifecycleProofBinding,
        ) -> Result<$permit<'store>, Error> {
            let proof = LifecycleProof::new(prior, attempted, expected, observed)?;
            let binding = MutationPermitBinding::validate(&proof, MutationAction::$action)?;
            store.commit_proof(&proof)?;
            Ok($permit::from_committed_proof(proof, binding))
        }
    };
}

commit_mutation_attempt!(commit_uki_publish_attempt, UkiPublishPermit, UkiPublish);
commit_mutation_attempt!(
    commit_boot_entry_create_attempt,
    BootEntryCreatePermit,
    BootEntryCreate
);
commit_mutation_attempt!(
    commit_boot_order_append_attempt,
    BootOrderAppendPermit,
    BootOrderAppend
);
commit_mutation_attempt!(
    commit_boot_order_remove_attempt,
    BootOrderRemovePermit,
    BootOrderRemove
);
commit_mutation_attempt!(
    commit_boot_entry_remove_attempt,
    BootEntryRemovePermit,
    BootEntryRemove
);
commit_mutation_attempt!(commit_uki_remove_attempt, UkiRemovePermit, UkiRemove);

fn commit_after_mutation<F: Filesystem>(
    store: &mut ArchProvisionStore<F>,
    attempted: &ArchProvisionState,
    next: ArchProvisionState,
    expected: LifecycleProofBinding,
    observed: LifecycleProofBinding,
    residual: Residual,
) -> Result<(), Error> {
    match commit(store, attempted.clone(), next.clone(), expected, observed) {
        Ok(()) => Ok(()),
        Err(commit_error) => {
            if matches!(store.load(), Ok(current) if current == next) {
                // The atomic replacement may have landed before a later durability error.  The
                // verified checkpoint is then the strongest durable evidence available; never
                // regress it or retry the external mutation.
                return Err(commit_error);
            }
            let mut retained = attempted.clone();
            add_residual(&mut retained, residual)?;
            match store.save(&retained) {
                Ok(()) => Err(commit_error),
                Err(save_error) => Err(save_error),
            }
        }
    }
}

fn commit_preserving<F: Filesystem>(
    store: &mut ArchProvisionStore<F>,
    prior: &ArchProvisionState,
    next: ArchProvisionState,
    expected: LifecycleProofBinding,
    observed: LifecycleProofBinding,
) -> Result<(), Error> {
    match commit(store, prior.clone(), next, expected, observed) {
        Ok(()) => Ok(()),
        Err(commit_error) => match store.save(prior) {
            Ok(()) => Err(commit_error),
            Err(save_error) => Err(save_error),
        },
    }
}

fn fail_at<F: Filesystem>(
    store: &mut ArchProvisionStore<F>,
    attempt: &ArchProvisionState,
    failure: LifecycleFailure,
) -> Result<ArchProvisionState, Error> {
    match &failure {
        LifecycleFailure::Stopped { residual, .. }
        | LifecycleFailure::Uncertain { residual, .. } => {
            let mut retained = attempt.clone();
            add_residual(&mut retained, *residual)?;
            store.save(&retained)?;
        }
        LifecycleFailure::Rejected(_) => {}
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

fn residual_for_state(state: &ArchProvisionState) -> Option<Residual> {
    match state {
        ArchProvisionState::Provisioning(record) => match record.step {
            ProvisioningStep::UkiPublicationPending
            | ProvisioningStep::UkiPublicationAttempted
            | ProvisioningStep::UkiPublished => Some(Residual::UkiMayRemain),
            ProvisioningStep::BootEntryCreateAttempted
            | ProvisioningStep::BootEntryCreated
            | ProvisioningStep::BootEntryReadBackVerified => Some(Residual::BootEntryMayExist),
            ProvisioningStep::BootOrderAppendAttempted
            | ProvisioningStep::BootOrderAppendWriteCompleted
            | ProvisioningStep::BootOrderAppended
            | ProvisioningStep::BootOrderReadBackVerified => {
                Some(Residual::BootOrderMayContainEntry)
            }
        },
        ArchProvisionState::Uninstalling(record) => match record.step {
            UninstallingStep::Started
            | UninstallingStep::BootOrderRemovalAttempted
            | UninstallingStep::BootOrderRemovalWriteCompleted
            | UninstallingStep::BootOrderRemoved
            | UninstallingStep::BootOrderRemovalReadBackVerified => {
                Some(Residual::BootOrderMayContainEntry)
            }
            UninstallingStep::BootEntryRemovalAttempted
            | UninstallingStep::BootEntryDeleteCompleted
            | UninstallingStep::BootEntryRemoved
            | UninstallingStep::BootEntryRemovalReadBackVerified => {
                Some(Residual::BootEntryMayExist)
            }
            UninstallingStep::UkiRemovalAttempted
            | UninstallingStep::UkiDeleteCompleted
            | UninstallingStep::UkiRemoved => Some(Residual::UkiMayRemain),
        },
        ArchProvisionState::Unprovisioned
        | ArchProvisionState::Ready(_)
        | ArchProvisionState::Uninstalled(_) => None,
    }
}

fn require_precondition_at<F: Filesystem>(
    store: &mut ArchProvisionStore<F>,
    prior: &ArchProvisionState,
    actual: &LifecycleReadback,
    expected: &LifecycleReadback,
    residual: Residual,
) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        fail_precondition(store, prior, residual, Error::ReadbackFailed)
    }
}

fn fail_precondition<F: Filesystem, T>(
    store: &mut ArchProvisionStore<F>,
    prior: &ArchProvisionState,
    residual: Residual,
    error: Error,
) -> Result<T, Error> {
    let mut retained = prior.clone();
    add_residual(&mut retained, residual)?;
    store.save(&retained)?;
    Err(error)
}

fn require_readback_at<F: Filesystem>(
    store: &mut ArchProvisionStore<F>,
    attempt: &ArchProvisionState,
    actual: &LifecycleReadback,
    expected: &LifecycleReadback,
    residual: Residual,
) -> Result<(), Error> {
    if actual == expected {
        return Ok(());
    }
    let mut retained = attempt.clone();
    add_residual(&mut retained, residual)?;
    store.save(&retained)?;
    Err(Error::ReadbackFailed)
}

fn uki_matches(entry: &OwnedArchEntry, readback: &LifecycleReadback) -> bool {
    matches!(
        (entry.publish.as_ref(), readback),
        (Some(expected), LifecycleReadback::UkiPresent(actual)) if expected == actual
    )
}

fn uki_matches_recovery_checkpoint(
    state: &ArchProvisionState,
    entry: &OwnedArchEntry,
    readback: &LifecycleReadback,
) -> bool {
    match state {
        ArchProvisionState::Uninstalling(record) if record.step == UninstallingStep::UkiRemoved => {
            matches!(readback, LifecycleReadback::UkiAbsent)
        }
        _ => uki_matches(entry, readback),
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
            LifecycleProofBinding::BootEntryPresent,
            LifecycleProofBinding::BootEntryAbsent,
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
            LifecycleProofBinding::BootEntryPresent,
            LifecycleProofBinding::BootEntryAbsent,
        )
        .unwrap();
        assert_eq!(mismatched.validate(&prior), Err(Error::ReadbackFailed));
        assert_eq!(
            mismatched.validate(&verified_state("op-1")),
            Err(Error::ReadbackFailed)
        );
    }

    #[test]
    fn proof_bindings_are_checked_for_attempted_and_intermediate_terminal_steps() {
        let published = verified_state("op-1");
        let entry_attempt = provisioning_step(
            &published,
            ProvisioningStep::BootEntryCreateAttempted,
            Some(PublishMetadata {
                sha256: [1; 32],
                size: 1,
            }),
        )
        .unwrap();
        let forged_attempt = LifecycleProof::new(
            published.clone(),
            entry_attempt.clone(),
            LifecycleProofBinding::BootEntryAbsent,
            LifecycleProofBinding::BootEntryAbsent,
        )
        .unwrap();
        assert_eq!(
            forged_attempt.validate(&published),
            Err(Error::ReadbackFailed)
        );

        let created = provisioning_step(
            &entry_attempt,
            ProvisioningStep::BootEntryCreated,
            Some(PublishMetadata {
                sha256: [1; 32],
                size: 1,
            }),
        )
        .unwrap();
        let valid_created = LifecycleProof::new(
            entry_attempt.clone(),
            created.clone(),
            LifecycleProofBinding::BootEntryPresent,
            LifecycleProofBinding::BootEntryPresent,
        )
        .unwrap();
        assert!(valid_created.validate(&entry_attempt).is_ok());

        let order_attempt = provisioning_step(
            &created,
            ProvisioningStep::BootOrderAppendAttempted,
            Some(PublishMetadata {
                sha256: [1; 32],
                size: 1,
            }),
        )
        .unwrap();
        let appended = provisioning_step(
            &order_attempt,
            ProvisioningStep::BootOrderAppended,
            Some(PublishMetadata {
                sha256: [1; 32],
                size: 1,
            }),
        )
        .unwrap();
        let forged_appended = LifecycleProof::new(
            order_attempt.clone(),
            appended,
            LifecycleProofBinding::BootOrderBefore(
                BootOrderValue::new(7, vec![BootId(7)]).unwrap(),
            ),
            LifecycleProofBinding::BootOrderBefore(
                BootOrderValue::new(7, vec![BootId(7)]).unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(
            forged_appended.validate(&order_attempt),
            Err(Error::ReadbackFailed)
        );
    }
}
