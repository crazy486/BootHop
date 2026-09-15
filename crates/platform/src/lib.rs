use boothop_core::{Error, RecordState, TargetRecord};

/// A trusted record store used while its operation guard is alive.
/// Only a verified absent record is Missing; unknown/corrupt records must not be overwritten.
pub trait ProtectedStore {
    fn load(&mut self) -> Result<RecordState, Error>;
    fn save(&mut self, target: &TargetRecord) -> Result<(), Error>;
}

#[cfg(target_os = "linux")]
pub mod linux;

pub mod windows;
