//! Closed wire DTOs. No protected record or firmware identity is serializable here.
use boothop_core as c;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
pub const MAX_BYTES: usize = 65_536;
pub const PROTOCOL_VERSION: u32 = 2;
const MAX_COMPACT_STAGES: usize = 256;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Invalid,
    Version,
    ResourceLimit,
    Truncated,
}

/// Correlation data for exactly one GUI invocation.  This is deliberately
/// opaque to the semantic protocol and is never accepted as an authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(String);

impl RequestId {
    pub fn generate() -> Result<Self, ProtocolError> {
        loop {
            let mut bytes = [0_u8; 16];
            getrandom::fill(&mut bytes).map_err(|_| ProtocolError::Invalid)?;
            if bytes != [0; 16] {
                return Ok(Self::from_bytes(bytes));
            }
        }
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let mut text = std::string::String::with_capacity(32);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            text.push(HEX[(byte >> 4) as usize] as char);
            text.push(HEX[(byte & 0x0f) as usize] as char);
        }
        // A zero ID is never emitted by the production generator. Keep the
        // constructor useful for tests while decode/validation remains strict.
        Self(text)
    }

    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || value.bytes().all(|byte| byte == b'0')
        {
            return Err(ProtocolError::Invalid);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for RequestId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|_| serde::de::Error::custom("invalid request_id"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEnvelope {
    pub request_id: RequestId,
    pub request: c::Request,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseEnvelope {
    pub request_id: RequestId,
    pub result: Result<c::Report, c::Error>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BootId(u16);
impl From<c::BootId> for BootId {
    fn from(v: c::BootId) -> Self {
        Self(v.0)
    }
}
impl From<BootId> for c::BootId {
    fn from(v: BootId) -> Self {
        Self(v.0)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Os {
    Windows,
    Linux,
}
impl From<c::Os> for Os {
    fn from(v: c::Os) -> Self {
        match v {
            c::Os::Windows => Self::Windows,
            c::Os::Linux => Self::Linux,
        }
    }
}
impl From<Os> for c::Os {
    fn from(v: Os) -> Self {
        match v {
            Os::Windows => Self::Windows,
            Os::Linux => Self::Linux,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Request {
    Inspect,
    Configure { boot_id: BootId, os: Os },
    Switch { os: Os },
}
impl From<c::Request> for Request {
    fn from(v: c::Request) -> Self {
        match v {
            c::Request::Inspect => Self::Inspect,
            c::Request::Configure { boot_id, os } => Self::Configure {
                boot_id: boot_id.into(),
                os: os.into(),
            },
            c::Request::Switch { os } => Self::Switch { os: os.into() },
        }
    }
}
impl From<Request> for c::Request {
    fn from(v: Request) -> Self {
        match v {
            Request::Inspect => Self::Inspect,
            Request::Configure { boot_id, os } => Self::Configure {
                boot_id: boot_id.into(),
                os: os.into(),
            },
            Request::Switch { os } => Self::Switch { os: os.into() },
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Stage {
    TargetValidated,
    BootNextVerified,
    RebootAccepted,
    RebootRejected,
    RebootUnknown,
    RollbackAttempted,
    RollbackRestored,
    RollbackUnsafe,
    RollbackFailed,
    ResidualPossible,
}
impl From<c::Stage> for Stage {
    fn from(v: c::Stage) -> Self {
        match v {
            c::Stage::TargetValidated => Self::TargetValidated,
            c::Stage::BootNextVerified => Self::BootNextVerified,
            c::Stage::RebootAccepted => Self::RebootAccepted,
            c::Stage::RebootRejected => Self::RebootRejected,
            c::Stage::RebootUnknown => Self::RebootUnknown,
            c::Stage::RollbackAttempted => Self::RollbackAttempted,
            c::Stage::RollbackRestored => Self::RollbackRestored,
            c::Stage::RollbackUnsafe => Self::RollbackUnsafe,
            c::Stage::RollbackFailed => Self::RollbackFailed,
            c::Stage::ResidualPossible => Self::ResidualPossible,
        }
    }
}
impl From<Stage> for c::Stage {
    fn from(v: Stage) -> Self {
        match v {
            Stage::TargetValidated => Self::TargetValidated,
            Stage::BootNextVerified => Self::BootNextVerified,
            Stage::RebootAccepted => Self::RebootAccepted,
            Stage::RebootRejected => Self::RebootRejected,
            Stage::RebootUnknown => Self::RebootUnknown,
            Stage::RollbackAttempted => Self::RollbackAttempted,
            Stage::RollbackRestored => Self::RollbackRestored,
            Stage::RollbackUnsafe => Self::RollbackUnsafe,
            Stage::RollbackFailed => Self::RollbackFailed,
            Stage::ResidualPossible => Self::ResidualPossible,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RecordDiagnostic {
    Missing,
    Ready { boot_id: BootId, os: Os },
}
impl From<c::RecordDiagnostic> for RecordDiagnostic {
    fn from(v: c::RecordDiagnostic) -> Self {
        match v {
            c::RecordDiagnostic::Missing => Self::Missing,
            c::RecordDiagnostic::Ready { boot_id, os } => Self::Ready {
                boot_id: boot_id.into(),
                os: os.into(),
            },
        }
    }
}
impl From<RecordDiagnostic> for c::RecordDiagnostic {
    fn from(v: RecordDiagnostic) -> Self {
        match v {
            RecordDiagnostic::Missing => Self::Missing,
            RecordDiagnostic::Ready { boot_id, os } => Self::Ready {
                boot_id: boot_id.into(),
                os: os.into(),
            },
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Classification {
    NeedsConfirmation,
    Unsupported,
}
impl From<c::Classification> for Classification {
    fn from(v: c::Classification) -> Self {
        match v {
            c::Classification::NeedsConfirmation => Self::NeedsConfirmation,
            c::Classification::Unsupported => Self::Unsupported,
        }
    }
}
impl From<Classification> for c::Classification {
    fn from(v: Classification) -> Self {
        match v {
            Classification::NeedsConfirmation => Self::NeedsConfirmation,
            Classification::Unsupported => Self::Unsupported,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EnumerationDiagnostic {
    DuplicateBootOrder(BootId),
}
impl From<c::EnumerationDiagnostic> for EnumerationDiagnostic {
    fn from(v: c::EnumerationDiagnostic) -> Self {
        match v {
            c::EnumerationDiagnostic::DuplicateBootOrder(v) => Self::DuplicateBootOrder(v.into()),
        }
    }
}
impl From<EnumerationDiagnostic> for c::EnumerationDiagnostic {
    fn from(v: EnumerationDiagnostic) -> Self {
        match v {
            EnumerationDiagnostic::DuplicateBootOrder(v) => Self::DuplicateBootOrder(v.into()),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ResidualAssessment {
    NotChecked,
    Observed(Option<BootId>),
    ReadFailed(Box<Error>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RollbackAssessment {
    NotNeeded,
    Restored,
    Unsafe,
    Failed(Box<Error>),
}
impl From<c::RollbackAssessment> for RollbackAssessment {
    fn from(v: c::RollbackAssessment) -> Self {
        match v {
            c::RollbackAssessment::NotNeeded => Self::NotNeeded,
            c::RollbackAssessment::Restored => Self::Restored,
            c::RollbackAssessment::Unsafe => Self::Unsafe,
            c::RollbackAssessment::Failed(e) => Self::Failed(Box::new((*e).into())),
        }
    }
}
impl From<RollbackAssessment> for c::RollbackAssessment {
    fn from(v: RollbackAssessment) -> Self {
        match v {
            RollbackAssessment::NotNeeded => Self::NotNeeded,
            RollbackAssessment::Restored => Self::Restored,
            RollbackAssessment::Unsafe => Self::Unsafe,
            RollbackAssessment::Failed(e) => Self::Failed(Box::new((*e).into())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
impl From<c::PlatformOperation> for PlatformOperation {
    fn from(v: c::PlatformOperation) -> Self {
        match v {
            c::PlatformOperation::Open => Self::Open,
            c::PlatformOperation::Read => Self::Read,
            c::PlatformOperation::Write => Self::Write,
            c::PlatformOperation::Metadata => Self::Metadata,
            c::PlatformOperation::Lock => Self::Lock,
            c::PlatformOperation::Flush => Self::Flush,
            c::PlatformOperation::Replace => Self::Replace,
            c::PlatformOperation::Ipc => Self::Ipc,
            c::PlatformOperation::Reboot => Self::Reboot,
            c::PlatformOperation::Random => Self::Random,
            c::PlatformOperation::Process => Self::Process,
            c::PlatformOperation::Security => Self::Security,
        }
    }
}
impl From<PlatformOperation> for c::PlatformOperation {
    fn from(v: PlatformOperation) -> Self {
        match v {
            PlatformOperation::Open => Self::Open,
            PlatformOperation::Read => Self::Read,
            PlatformOperation::Write => Self::Write,
            PlatformOperation::Metadata => Self::Metadata,
            PlatformOperation::Lock => Self::Lock,
            PlatformOperation::Flush => Self::Flush,
            PlatformOperation::Replace => Self::Replace,
            PlatformOperation::Ipc => Self::Ipc,
            PlatformOperation::Reboot => Self::Reboot,
            PlatformOperation::Random => Self::Random,
            PlatformOperation::Process => Self::Process,
            PlatformOperation::Security => Self::Security,
        }
    }
}
impl From<c::ResidualAssessment> for ResidualAssessment {
    fn from(v: c::ResidualAssessment) -> Self {
        match v {
            c::ResidualAssessment::NotChecked => Self::NotChecked,
            c::ResidualAssessment::Observed(v) => Self::Observed(v.map(|v| v.into())),
            c::ResidualAssessment::ReadFailed(v) => Self::ReadFailed(Box::new((*v).into())),
        }
    }
}
impl From<ResidualAssessment> for c::ResidualAssessment {
    fn from(v: ResidualAssessment) -> Self {
        match v {
            ResidualAssessment::NotChecked => Self::NotChecked,
            ResidualAssessment::Observed(v) => Self::Observed(v.map(|v| v.into())),
            ResidualAssessment::ReadFailed(v) => Self::ReadFailed(Box::new((*v).into())),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        diagnostics: Vec<EnumerationDiagnostic>,
    },
}
impl From<c::Error> for Error {
    fn from(v: c::Error) -> Self {
        match v {
            c::Error::MalformedLoadOption => Self::MalformedLoadOption,
            c::Error::MalformedDevicePath => Self::MalformedDevicePath,
            c::Error::ResourceLimit => Self::ResourceLimit,
            c::Error::UnsupportedFormat => Self::UnsupportedFormat,
            c::Error::UnsupportedRecordVersion { found } => {
                Self::UnsupportedRecordVersion { found }
            }
            c::Error::UnsupportedIdentityComponent => Self::UnsupportedIdentityComponent,
            c::Error::CorruptRecord => Self::CorruptRecord,
            c::Error::IdentityMismatch => Self::IdentityMismatch,
            c::Error::UnexpectedOs => Self::UnexpectedOs,
            c::Error::TargetMissing => Self::TargetMissing,
            c::Error::NotConfigured => Self::NotConfigured,
            c::Error::BootNextConflict => Self::BootNextConflict,
            c::Error::Busy => Self::Busy,
            c::Error::ReadbackFailed => Self::ReadbackFailed,
            c::Error::RebootRejected => Self::RebootRejected,
            c::Error::NotUefi => Self::NotUefi,
            c::Error::PrivilegeUnavailable => Self::PrivilegeUnavailable,
            c::Error::PrivilegeEnableFailed { raw_code } => {
                Self::PrivilegeEnableFailed { raw_code }
            }
            c::Error::PrivilegeRestoreFailed { raw_code } => {
                Self::PrivilegeRestoreFailed { raw_code }
            }
            c::Error::FirmwareReadFailed { raw_code } => Self::FirmwareReadFailed { raw_code },
            c::Error::FirmwareWriteFailed { raw_code } => Self::FirmwareWriteFailed { raw_code },
            c::Error::BootNextUnavailable { raw_code } => Self::BootNextUnavailable { raw_code },
            c::Error::ProtectedStoreViolation { raw_code } => {
                Self::ProtectedStoreViolation { raw_code }
            }
            c::Error::StoreReplaceFailed { raw_code } => Self::StoreReplaceFailed { raw_code },
            c::Error::PlatformIo {
                operation,
                raw_code,
            } => Self::PlatformIo {
                operation: operation.into(),
                raw_code,
            },
            c::Error::StoreDurabilityUnknown { raw_code } => {
                Self::StoreDurabilityUnknown { raw_code }
            }
            c::Error::FlowFailure {
                cause,
                stages,
                residual_assessment,
                rollback_assessment,
                diagnostics,
            } => Self::FlowFailure {
                cause: Box::new((*cause).into()),
                stages: stages.into_iter().map(|v| v.into()).collect(),
                residual_assessment: residual_assessment.into(),
                rollback_assessment: rollback_assessment.into(),
                diagnostics: diagnostics.into_iter().map(|v| v.into()).collect(),
            },
        }
    }
}
impl From<Error> for c::Error {
    fn from(v: Error) -> Self {
        match v {
            Error::MalformedLoadOption => Self::MalformedLoadOption,
            Error::MalformedDevicePath => Self::MalformedDevicePath,
            Error::ResourceLimit => Self::ResourceLimit,
            Error::UnsupportedFormat => Self::UnsupportedFormat,
            Error::UnsupportedRecordVersion { found } => Self::UnsupportedRecordVersion { found },
            Error::UnsupportedIdentityComponent => Self::UnsupportedIdentityComponent,
            Error::CorruptRecord => Self::CorruptRecord,
            Error::IdentityMismatch => Self::IdentityMismatch,
            Error::UnexpectedOs => Self::UnexpectedOs,
            Error::TargetMissing => Self::TargetMissing,
            Error::NotConfigured => Self::NotConfigured,
            Error::BootNextConflict => Self::BootNextConflict,
            Error::Busy => Self::Busy,
            Error::ReadbackFailed => Self::ReadbackFailed,
            Error::RebootRejected => Self::RebootRejected,
            Error::NotUefi => Self::NotUefi,
            Error::PrivilegeUnavailable => Self::PrivilegeUnavailable,
            Error::PrivilegeEnableFailed { raw_code } => Self::PrivilegeEnableFailed { raw_code },
            Error::PrivilegeRestoreFailed { raw_code } => Self::PrivilegeRestoreFailed { raw_code },
            Error::FirmwareReadFailed { raw_code } => Self::FirmwareReadFailed { raw_code },
            Error::FirmwareWriteFailed { raw_code } => Self::FirmwareWriteFailed { raw_code },
            Error::BootNextUnavailable { raw_code } => Self::BootNextUnavailable { raw_code },
            Error::ProtectedStoreViolation { raw_code } => {
                Self::ProtectedStoreViolation { raw_code }
            }
            Error::StoreReplaceFailed { raw_code } => Self::StoreReplaceFailed { raw_code },
            Error::PlatformIo {
                operation,
                raw_code,
            } => Self::PlatformIo {
                operation: operation.into(),
                raw_code,
            },
            Error::StoreDurabilityUnknown { raw_code } => Self::StoreDurabilityUnknown { raw_code },
            Error::FlowFailure {
                cause,
                stages,
                residual_assessment,
                rollback_assessment,
                diagnostics,
            } => Self::FlowFailure {
                cause: Box::new((*cause).into()),
                stages: stages.into_iter().map(|v| v.into()).collect(),
                residual_assessment: residual_assessment.into(),
                rollback_assessment: rollback_assessment.into(),
                diagnostics: diagnostics.into_iter().map(|v| v.into()).collect(),
            },
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub boot_id: BootId,
    pub description_utf16: Vec<u16>,
    pub classification: Classification,
    pub ambiguous: bool,
}
impl From<c::Candidate> for Candidate {
    fn from(v: c::Candidate) -> Self {
        Self {
            boot_id: v.boot_id.into(),
            description_utf16: v.description_utf16,
            classification: v.classification.into(),
            ambiguous: v.ambiguous,
        }
    }
}
impl From<Candidate> for c::Candidate {
    fn from(v: Candidate) -> Self {
        Self {
            boot_id: v.boot_id.into(),
            description_utf16: v.description_utf16,
            classification: v.classification.into(),
            ambiguous: v.ambiguous,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub candidates: Vec<Candidate>,
    pub record: RecordDiagnostic,
    pub stages: Vec<Stage>,
    pub diagnostics: Vec<EnumerationDiagnostic>,
}
impl From<c::Report> for Report {
    fn from(v: c::Report) -> Self {
        Self {
            candidates: v.candidates.into_iter().map(|v| v.into()).collect(),
            record: v.record.into(),
            stages: v.stages.into_iter().map(|v| v.into()).collect(),
            diagnostics: v.diagnostics.into_iter().map(|v| v.into()).collect(),
        }
    }
}
impl From<Report> for c::Report {
    fn from(v: Report) -> Self {
        Self {
            candidates: v.candidates.into_iter().map(|v| v.into()).collect(),
            record: v.record.into(),
            stages: v.stages.into_iter().map(|v| v.into()).collect(),
            diagnostics: v.diagnostics.into_iter().map(|v| v.into()).collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    protocol_version: u32,
    request_id: RequestId,
    request: Request,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    protocol_version: u32,
    request_id: RequestId,
    result: Result<Report, Error>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    protocol_version: u32,
    hello: bool,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    // A capped writer bounds allocation as well as the on-wire output.
    struct Capped(Vec<u8>);
    impl std::io::Write for Capped {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len() + bytes.len() > MAX_BYTES {
                return Err(std::io::ErrorKind::OutOfMemory.into());
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = Capped(vec![0; 4]);
    serde_json::to_writer(&mut out, value).map_err(|_| ProtocolError::ResourceLimit)?;
    let length = (out.0.len() - 4) as u32;
    out.0[..4].copy_from_slice(&length.to_le_bytes());
    Ok(out.0)
}
fn decode<T: DeserializeOwned + Serialize>(frame: &[u8]) -> Result<T, ProtocolError> {
    if frame.len() > MAX_BYTES {
        return Err(ProtocolError::ResourceLimit);
    }
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(ProtocolError::Truncated)?
        .try_into()
        .unwrap();
    let size = u32::from_le_bytes(prefix) as usize;
    if size > MAX_BYTES - 4 {
        return Err(ProtocolError::ResourceLimit);
    }
    if frame.len() < size + 4 {
        return Err(ProtocolError::Truncated);
    }
    if frame.len() != size + 4 {
        return Err(ProtocolError::Invalid);
    }
    // Reject duplicate object members from the original bytes before any
    // typed/value decode can normalize an object map.
    reject_duplicate_keys(&frame[4..])?;
    // Decode the ORIGINAL bytes first: typed visitors must see unknown fields.
    // Serde also accepts
    // sequences for structs and {"UnitVariant": null} for unit enums, so typed
    // decoding alone is not a strict JSON shape check.
    let value: T = serde_json::from_slice(&frame[4..]).map_err(|_| ProtocolError::Invalid)?;
    let received: serde_json::Value =
        serde_json::from_slice(&frame[4..]).map_err(|_| ProtocolError::Invalid)?;
    let canonical = serde_json::to_value(&value).map_err(|_| ProtocolError::Invalid)?;
    // Structural equality enforces the serializer's map-only structs and
    // string-only unit enums recursively for EVERY reachable DTO, without a
    // separate shape schema that can drift. Object field ordering, whitespace
    // and equivalent JSON escapes remain irrelevant; array ordering does not.
    if received != canonical {
        return Err(ProtocolError::Invalid);
    }
    Ok(value)
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), ProtocolError> {
    let mut parser = JsonScanner { bytes, offset: 0 };
    parser.value(0)?;
    parser.whitespace();
    if parser.offset == bytes.len() {
        Ok(())
    } else {
        Err(ProtocolError::Invalid)
    }
}

struct JsonScanner<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl JsonScanner<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.offset += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), ProtocolError> {
        if depth > 256 {
            return Err(ProtocolError::ResourceLimit);
        }
        self.whitespace();
        match self.bytes.get(self.offset).copied() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(|_| ()),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(ProtocolError::Invalid),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), ProtocolError> {
        self.offset += 1;
        self.whitespace();
        let mut keys = std::collections::HashSet::new();
        if self.bytes.get(self.offset) == Some(&b'}') {
            self.offset += 1;
            return Ok(());
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            if !keys.insert(key) {
                return Err(ProtocolError::Invalid);
            }
            self.whitespace();
            if self.bytes.get(self.offset) != Some(&b':') {
                return Err(ProtocolError::Invalid);
            }
            self.offset += 1;
            self.value(depth)?;
            self.whitespace();
            match self.bytes.get(self.offset).copied() {
                Some(b',') => self.offset += 1,
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(());
                }
                _ => return Err(ProtocolError::Invalid),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), ProtocolError> {
        self.offset += 1;
        self.whitespace();
        if self.bytes.get(self.offset) == Some(&b']') {
            self.offset += 1;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.whitespace();
            match self.bytes.get(self.offset).copied() {
                Some(b',') => self.offset += 1,
                Some(b']') => {
                    self.offset += 1;
                    return Ok(());
                }
                _ => return Err(ProtocolError::Invalid),
            }
        }
    }

    fn string(&mut self) -> Result<String, ProtocolError> {
        let start = self.offset;
        if self.bytes.get(self.offset) != Some(&b'"') {
            return Err(ProtocolError::Invalid);
        }
        self.offset += 1;
        loop {
            match self.bytes.get(self.offset).copied() {
                Some(b'"') => {
                    self.offset += 1;
                    return serde_json::from_slice(&self.bytes[start..self.offset])
                        .map_err(|_| ProtocolError::Invalid);
                }
                Some(b'\\') => {
                    self.offset += 1;
                    if self.bytes.get(self.offset) == Some(&b'u') {
                        self.offset = self.offset.saturating_add(5);
                    } else {
                        self.offset += 1;
                    }
                }
                Some(byte) if byte < 0x20 => return Err(ProtocolError::Invalid),
                Some(_) => self.offset += 1,
                None => return Err(ProtocolError::Invalid),
            }
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), ProtocolError> {
        if self.bytes.get(self.offset..self.offset + literal.len()) == Some(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(ProtocolError::Invalid)
        }
    }

    fn number(&mut self) -> Result<(), ProtocolError> {
        let start = self.offset;
        if self.bytes.get(self.offset) == Some(&b'-') {
            self.offset += 1;
        }
        match self.bytes.get(self.offset) {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while self
                    .bytes
                    .get(self.offset)
                    .is_some_and(|byte| byte.is_ascii_digit())
                {
                    self.offset += 1;
                }
            }
            _ => return Err(ProtocolError::Invalid),
        }
        if self.bytes.get(self.offset) == Some(&b'.') {
            self.offset += 1;
            let fraction = self.offset;
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| byte.is_ascii_digit())
            {
                self.offset += 1;
            }
            if self.offset == fraction {
                return Err(ProtocolError::Invalid);
            }
        }
        if self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| *byte == b'e' || *byte == b'E')
        {
            self.offset += 1;
            if self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| *byte == b'+' || *byte == b'-')
            {
                self.offset += 1;
            }
            let exponent = self.offset;
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| byte.is_ascii_digit())
            {
                self.offset += 1;
            }
            if self.offset == exponent {
                return Err(ProtocolError::Invalid);
            }
        }
        if self.offset == start {
            Err(ProtocolError::Invalid)
        } else {
            Ok(())
        }
    }
}
fn version(v: u32) -> Result<(), ProtocolError> {
    if v == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::Version)
    }
}
pub fn encode_request_with_id(
    request_id: &RequestId,
    request: c::Request,
) -> Result<Vec<u8>, ProtocolError> {
    RequestId::parse(request_id.as_str())?;
    encode(&WireRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: request_id.clone(),
        request: request.into(),
    })
}
pub fn encode_request(request: c::Request) -> Result<Vec<u8>, ProtocolError> {
    let request_id = RequestId::generate()?;
    encode_request_with_id(&request_id, request)
}
pub fn decode_request_envelope(frame: &[u8]) -> Result<RequestEnvelope, ProtocolError> {
    let wire: WireRequest = decode(frame)?;
    version(wire.protocol_version)?;
    Ok(RequestEnvelope {
        request_id: wire.request_id,
        request: wire.request.into(),
    })
}
pub fn decode_request(frame: &[u8]) -> Result<c::Request, ProtocolError> {
    Ok(decode_request_envelope(frame)?.request)
}
pub fn encode_response_with_id(
    request_id: &RequestId,
    result: Result<c::Report, c::Error>,
) -> Result<Vec<u8>, ProtocolError> {
    RequestId::parse(request_id.as_str())?;
    encode(&WireResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: request_id.clone(),
        result: result.map(Into::into).map_err(Into::into),
    })
}
pub fn encode_response(result: Result<c::Report, c::Error>) -> Result<Vec<u8>, ProtocolError> {
    let request_id = RequestId::generate()?;
    encode_response_with_id(&request_id, result)
}
pub fn decode_response_envelope(frame: &[u8]) -> Result<ResponseEnvelope, ProtocolError> {
    let wire: WireResponse = decode(frame)?;
    version(wire.protocol_version)?;
    Ok(ResponseEnvelope {
        request_id: wire.request_id,
        result: wire.result.map(Into::into).map_err(Into::into),
    })
}
pub fn decode_response(frame: &[u8]) -> Result<Result<c::Report, c::Error>, ProtocolError> {
    Ok(decode_response_envelope(frame)?.result)
}
pub fn decode_response_for(
    frame: &[u8],
    expected: &RequestId,
) -> Result<Result<c::Report, c::Error>, ProtocolError> {
    let response = decode_response_envelope(frame)?;
    if response.request_id != *expected {
        return Err(ProtocolError::Invalid);
    }
    Ok(response.result)
}
pub fn encode_hello() -> Vec<u8> {
    encode(&Hello {
        protocol_version: PROTOCOL_VERSION,
        hello: true,
    })
    .expect("fixed small Hello")
}
pub fn decode_hello(frame: &[u8]) -> Result<(), ProtocolError> {
    let hello: Hello = decode(frame)?;
    version(hello.protocol_version)?;
    if hello.hello {
        Ok(())
    } else {
        Err(ProtocolError::Invalid)
    }
}
/// Encode the entire response before writing. Hello and response share one budget.
pub fn budgeted_response(
    result: Result<c::Report, c::Error>,
    used: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let request_id = RequestId::generate()?;
    budgeted_response_with_id(&request_id, result, used)
}

pub fn budgeted_response_with_id(
    request_id: &RequestId,
    result: Result<c::Report, c::Error>,
    used: usize,
) -> Result<Vec<u8>, ProtocolError> {
    match encode_response_with_id(request_id, result.clone()) {
        Ok(frame) if frame.len() <= MAX_BYTES.saturating_sub(used) => Ok(frame),
        _ => {
            // Once a mutation stage exists, replacing the result with a plain
            // ResourceLimit would erase whether BootNext/reboot was attempted.
            // Keep a bounded terminal witness instead. Empty-stage reports are
            // pre-mutation inspection results and may safely use the generic
            // limit response.
            let compact = match result {
                Ok(report) if !report.stages.is_empty() => {
                    encode_response_with_id(request_id, Ok(compact_report(report)))
                }
                Err(c::Error::FlowFailure {
                    cause,
                    stages,
                    residual_assessment,
                    rollback_assessment,
                    ..
                }) if !stages.is_empty() => encode_response_with_id(
                    request_id,
                    Err(c::Error::FlowFailure {
                        cause: Box::new(compact_cause(*cause)),
                        stages: compact_stages(stages),
                        residual_assessment: compact_residual_assessment(residual_assessment),
                        rollback_assessment: compact_rollback_assessment(rollback_assessment),
                        diagnostics: Vec::new(),
                    }),
                ),
                _ => Err(ProtocolError::ResourceLimit),
            };
            let frame = compact
                .or_else(|_| encode_response_with_id(request_id, Err(c::Error::ResourceLimit)))?;
            if frame.len() <= MAX_BYTES.saturating_sub(used) {
                Ok(frame)
            } else {
                Err(ProtocolError::ResourceLimit)
            }
        }
    }
}

/// Keep the terminal domain classification when it is a bounded, trusted
/// value. Recursive failures and free-form payloads are collapsed so the
/// fallback itself cannot become another oversized response.
fn compact_cause(error: c::Error) -> c::Error {
    match error {
        c::Error::PlatformIo {
            operation,
            raw_code,
        } => c::Error::PlatformIo {
            operation,
            raw_code,
        },
        c::Error::FlowFailure { .. } => c::Error::ResourceLimit,
        other => other,
    }
}

fn compact_rollback_assessment(assessment: c::RollbackAssessment) -> c::RollbackAssessment {
    match assessment {
        c::RollbackAssessment::Failed(error) => {
            c::RollbackAssessment::Failed(Box::new(compact_cause(*error)))
        }
        other => other,
    }
}

fn compact_residual_assessment(assessment: c::ResidualAssessment) -> c::ResidualAssessment {
    match assessment {
        c::ResidualAssessment::NotChecked => c::ResidualAssessment::NotChecked,
        c::ResidualAssessment::Observed(boot_id) => c::ResidualAssessment::Observed(boot_id),
        c::ResidualAssessment::ReadFailed(error) => {
            c::ResidualAssessment::ReadFailed(Box::new(compact_cause(*error)))
        }
    }
}

fn compact_stages(stages: Vec<c::Stage>) -> Vec<c::Stage> {
    stages.into_iter().take(MAX_COMPACT_STAGES).collect()
}

fn compact_report(report: c::Report) -> c::Report {
    let target = match report.record {
        c::RecordDiagnostic::Ready { boot_id, .. } => Some(boot_id),
        c::RecordDiagnostic::Missing => None,
    };
    let candidates = target
        .and_then(|boot_id| {
            report
                .candidates
                .into_iter()
                .find(|candidate| candidate.boot_id == boot_id)
        })
        .map(|mut candidate| {
            candidate.description_utf16.clear();
            candidate
        })
        .into_iter()
        .collect();
    c::Report {
        candidates,
        record: report.record,
        stages: report.stages,
        diagnostics: Vec::new(),
    }
}
