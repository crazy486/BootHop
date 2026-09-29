use boothop_core::{ArchProvisionState, Error};

use super::store::{Filesystem, LockedStore};

/// Separate Arch ownership journal sharing the root-protected lock and directory.
pub struct ArchProvisionStore<F: Filesystem> {
    locked: LockedStore<F>,
}

impl<F: Filesystem> ArchProvisionStore<F> {
    pub fn acquire(fs: F) -> Result<Self, Error> {
        Ok(Self {
            locked: LockedStore::acquire(fs)?,
        })
    }

    pub fn load(&mut self) -> Result<ArchProvisionState, Error> {
        self.locked.load_arch_provision_state()
    }

    pub fn save(&mut self, state: &ArchProvisionState) -> Result<(), Error> {
        self.locked.save_arch_provision_state(state)
    }

    /// Final uninstall operation: replace the completed record with an owned tombstone.
    pub fn complete_uninstall(&mut self, state: &ArchProvisionState) -> Result<(), Error> {
        self.locked.complete_arch_uninstall(state)
    }
}
