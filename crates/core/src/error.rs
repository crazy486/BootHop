use crate::{BootId, Stage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformOperation {
    Open,
    Read,
    Write,
    Metadata,
    Lock,
    Flush,
    Replace,
    Ipc,
    Reboot,
    Random,
    Process,
    Security,
}

impl PlatformOperation {
    pub fn from_label(label: &str) -> Option<Self> {
        Some(match label {
            "open" => Self::Open,
            "read" => Self::Read,
            "write" => Self::Write,
            "metadata" => Self::Metadata,
            "lock" => Self::Lock,
            "fsync" | "flush" => Self::Flush,
            "rename" | "replace" => Self::Replace,
            "ipc" => Self::Ipc,
            "reboot" => Self::Reboot,
            "random" => Self::Random,
            "process" => Self::Process,
            "security" => Self::Security,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::Metadata => "metadata",
            Self::Lock => "lock",
            Self::Flush => "fsync",
            Self::Replace => "rename",
            Self::Ipc => "ipc",
            Self::Reboot => "reboot",
            Self::Random => "random",
            Self::Process => "process",
            Self::Security => "security",
        }
    }
}

impl From<&str> for PlatformOperation {
    fn from(value: &str) -> Self {
        Self::from_label(value).expect("unknown platform operation label")
    }
}
impl PartialEq<&str> for PlatformOperation {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

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
    NotUefi,
    PrivilegeUnavailable,
    PrivilegeEnableFailed {
        raw_code: i32,
    },
    PrivilegeRestoreFailed {
        raw_code: i32,
    },
    FirmwareReadFailed {
        raw_code: i32,
    },
    FirmwareWriteFailed {
        raw_code: i32,
    },
    BootNextUnavailable {
        raw_code: i32,
    },
    ProtectedStoreViolation {
        raw_code: i32,
    },
    StoreReplaceFailed {
        raw_code: i32,
    },
    PlatformIo {
        operation: PlatformOperation,
        raw_code: i32,
    },
    StoreDurabilityUnknown {
        raw_code: i32,
    },
    FlowFailure {
        cause: Box<Error>,
        stages: Vec<Stage>,
        residual_assessment: ResidualAssessment,
        rollback_assessment: RollbackAssessment,
        diagnostics: Vec<crate::EnumerationDiagnostic>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackAssessment {
    NotNeeded,
    Restored,
    Unsafe,
    Failed(Box<Error>),
}
