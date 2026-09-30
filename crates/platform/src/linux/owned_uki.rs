//! Exact-path, journal-hash-gated UKI cleanup boundary.

use boothop_core::{ArchProvisionState, Error, UninstallingStep};
use sha2::{Digest, Sha256};

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
    fn remove_fixed_if_expected(
        &mut self,
        path: &str,
        sha256: [u8; 32],
        size: u64,
    ) -> Result<(), Error>;
}

/// Delete the journal-owned UKI only when its fixed path is a regular file with the exact
/// journaled digest and size. The journal must already contain `UkiRemovalAttempted`.
pub fn remove_owned_uki<I: OwnedUkiIo>(
    io: &mut I,
    state: &mut ArchProvisionState,
) -> Result<(), Error> {
    let expected = match state {
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::UkiRemovalAttempted
                && record.residual.is_empty() =>
        {
            record
                .owned_entry
                .publish
                .as_ref()
                .ok_or(Error::CorruptRecord)
                .map(|metadata| (metadata.sha256, metadata.size))?
        }
        _ => return Err(Error::NotConfigured),
    };
    let current = io.inspect_fixed(FIXED_UKI_PATH)?;
    match current {
        OwnedUkiState::Regular { sha256, size } if (sha256, size) == expected => {}
        OwnedUkiState::Missing => return Err(Error::TargetMissing),
        OwnedUkiState::Regular { .. } => return Err(Error::IdentityMismatch),
        OwnedUkiState::Symlink | OwnedUkiState::Other => return Err(Error::IdentityMismatch),
    }
    io.remove_fixed_if_expected(FIXED_UKI_PATH, expected.0, expected.1)?;
    if io.inspect_fixed(FIXED_UKI_PATH)? != OwnedUkiState::Missing {
        return Err(Error::ReadbackFailed);
    }
    if let ArchProvisionState::Uninstalling(record) = state {
        record.step = UninstallingStep::UkiRemoved;
    }
    Ok(())
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
