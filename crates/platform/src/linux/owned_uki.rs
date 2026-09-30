//! Exact-path, journal-hash-gated UKI cleanup boundary.

use boothop_core::{ArchProvisionState, Error, UninstallingStep};
use sha2::{Digest, Sha256};

use super::coordinator::{LifecycleProofBinding, UkiRemovePermit};

const FIXED_UKI_PATH: &str = "EFI/BootHop/arch.efi";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedUkiState {
    Missing,
    Regular { sha256: [u8; 32], size: u64 },
    Symlink,
    Other,
}

/// Narrow filesystem capability used by uninstall. It cannot mount, resolve arbitrary paths,
/// or delete anything except the fixed path selected by this module.
pub trait OwnedUkiIo {
    fn inspect_fixed(&mut self, path: &str) -> Result<OwnedUkiState, Error>;
    /// Recheck the exact fixed-path file identity at the deletion boundary.
    fn remove_fixed_if_expected(&mut self, permit: UkiRemovePermit<'_>) -> Result<(), Error>;
}

/// Delete the journal-owned UKI only when its fixed path is a regular file with the exact
/// journaled digest and size. The journal must already contain `UkiRemovalAttempted`.
pub fn remove_owned_uki<I: OwnedUkiIo>(
    io: &mut I,
    permit: UkiRemovePermit<'_>,
) -> Result<(), Error> {
    let expected = validate_remove_permit(&permit)?;
    let current = io.inspect_fixed(FIXED_UKI_PATH)?;
    match current {
        OwnedUkiState::Regular { sha256, size } if (sha256, size) == expected => {}
        OwnedUkiState::Missing => return Err(Error::TargetMissing),
        OwnedUkiState::Regular { .. } => return Err(Error::IdentityMismatch),
        OwnedUkiState::Symlink | OwnedUkiState::Other => return Err(Error::IdentityMismatch),
    }
    io.remove_fixed_if_expected(permit)?;
    if io.inspect_fixed(FIXED_UKI_PATH)? != OwnedUkiState::Missing {
        return Err(Error::ReadbackFailed);
    }
    Ok(())
}

fn validate_remove_permit(permit: &UkiRemovePermit<'_>) -> Result<([u8; 32], u64), Error> {
    let entry = permit.owned_entry();
    let ArchProvisionState::Uninstalling(record) = permit.attempted_state() else {
        return Err(Error::NotConfigured);
    };
    if record.step != UninstallingStep::UkiRemovalAttempted
        || !record.residual.is_empty()
        || record.operation_id != permit.operation_id()
        || record.operation_version != permit.operation_version()
        || record.owned_entry != *entry
        || permit.expected_evidence() != &LifecycleProofBinding::UkiAbsent
    {
        return Err(Error::IdentityMismatch);
    }
    let metadata = entry.publish.as_ref().ok_or(Error::CorruptRecord)?;
    if permit.precondition_evidence() != &LifecycleProofBinding::Uki(metadata.clone()) {
        return Err(Error::IdentityMismatch);
    }
    Ok((metadata.sha256, metadata.size))
}

/// Reconcile an interrupted UKI removal read-only. The returned state is evidence only and
/// never authorizes another deletion.
pub fn observe_uki_removal<I: OwnedUkiIo>(
    io: &mut I,
    state: &ArchProvisionState,
) -> Result<OwnedUkiState, Error> {
    match state {
        ArchProvisionState::Uninstalling(record)
            if matches!(
                record.step,
                UninstallingStep::UkiRemovalAttempted
                    | UninstallingStep::UkiDeleteCompleted
                    | UninstallingStep::UkiRemoved
            ) =>
        {
            io.inspect_fixed(FIXED_UKI_PATH)
        }
        _ => Err(Error::NotConfigured),
    }
}

/// Helper for isolated fakes: calculate the same ownership tuple used by the journal.
pub fn digest_and_size(bytes: &[u8]) -> ([u8; 32], u64) {
    (Sha256::digest(bytes).into(), bytes.len() as u64)
}
