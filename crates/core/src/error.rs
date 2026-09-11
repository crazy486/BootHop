use crate::{BootId, Stage};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    MalformedLoadOption,
    MalformedDevicePath,
    ResourceLimit,
    UnsupportedFormat,
    UnsupportedRecordVersion {
        found: u64,
    },
    UnsupportedIdentityComponent,
    CorruptRecord,
    IdentityMismatch,
    UnexpectedOs,
    TargetMissing,
    NotConfigured,
    BootNextConflict,
    Busy,
    ReadbackFailed,
    RebootRejected,
    /// Operation is a fixed diagnostic label: open/read/write/metadata/lock/fsync/rename/ipc/reboot.
    /// Adapters must never include paths or variable contents.
    PlatformIo {
        operation: String,
        raw_code: i32,
    },
    StoreDurabilityUnknown {
        raw_code: i32,
    },
    FlowFailure {
        cause: Box<Error>,
        stages: Vec<Stage>,
        residual_assessment: ResidualAssessment,
    },
}

impl Error {
    /// Derived from the completed stage list so there is only one source of truth.
    pub fn residual_possible(&self) -> bool {
        match self {
            Self::FlowFailure { stages, .. } => stages.contains(&Stage::ResidualPossible),
            Self::StoreDurabilityUnknown { .. } => true,
            _ => false,
        }
    }
}

/// One post-rejection observation, not a guarantee against subsequent external changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResidualAssessment {
    NotChecked,
    Observed(Option<BootId>),
    ReadFailed(Box<Error>),
}
