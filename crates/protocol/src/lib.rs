//! Version 1 wire DTOs. No protected record or firmware identity is serializable here.
use boothop_core as c;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
pub const MAX_BYTES: usize = 65_536;
pub const PROTOCOL_VERSION: u32 = 1;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Invalid,
    Version,
    ResourceLimit,
    Truncated,
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
            c::Error::PlatformIo {
                operation,
                raw_code,
            } => Self::PlatformIo {
                operation,
                raw_code,
            },
            c::Error::StoreDurabilityUnknown { raw_code } => {
                Self::StoreDurabilityUnknown { raw_code }
            }
            c::Error::FlowFailure {
                cause,
                stages,
                residual_assessment,
                diagnostics,
            } => Self::FlowFailure {
                cause: Box::new((*cause).into()),
                stages: stages.into_iter().map(|v| v.into()).collect(),
                residual_assessment: residual_assessment.into(),
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
            Error::PlatformIo {
                operation,
                raw_code,
            } => Self::PlatformIo {
                operation,
                raw_code,
            },
            Error::StoreDurabilityUnknown { raw_code } => Self::StoreDurabilityUnknown { raw_code },
            Error::FlowFailure {
                cause,
                stages,
                residual_assessment,
                diagnostics,
            } => Self::FlowFailure {
                cause: Box::new((*cause).into()),
                stages: stages.into_iter().map(|v| v.into()).collect(),
                residual_assessment: residual_assessment.into(),
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
    request: Request,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    protocol_version: u32,
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
    // Decode the ORIGINAL bytes first: typed visitors must see duplicate and
    // unknown fields before any Value map can collapse keys. Serde also accepts
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
fn version(v: u32) -> Result<(), ProtocolError> {
    if v == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::Version)
    }
}
pub fn encode_request(request: c::Request) -> Result<Vec<u8>, ProtocolError> {
    encode(&WireRequest {
        protocol_version: PROTOCOL_VERSION,
        request: request.into(),
    })
}
pub fn decode_request(frame: &[u8]) -> Result<c::Request, ProtocolError> {
    let wire: WireRequest = decode(frame)?;
    version(wire.protocol_version)?;
    Ok(wire.request.into())
}
pub fn encode_response(result: Result<c::Report, c::Error>) -> Result<Vec<u8>, ProtocolError> {
    encode(&WireResponse {
        protocol_version: PROTOCOL_VERSION,
        result: result.map(Into::into).map_err(Into::into),
    })
}
pub fn decode_response(frame: &[u8]) -> Result<Result<c::Report, c::Error>, ProtocolError> {
    let wire: WireResponse = decode(frame)?;
    version(wire.protocol_version)?;
    Ok(wire.result.map(Into::into).map_err(Into::into))
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
    match encode_response(result.clone()) {
        Ok(frame) if frame.len() <= MAX_BYTES.saturating_sub(used) => Ok(frame),
        _ => {
            // Once a mutation stage exists, replacing the result with a plain
            // ResourceLimit would erase whether BootNext/reboot was attempted.
            // Keep a bounded terminal witness instead. Empty-stage reports are
            // pre-mutation inspection results and may safely use the generic
            // limit response.
            let compact = match result {
                Ok(report) if !report.stages.is_empty() => {
                    encode_response(Ok(compact_report(report)))
                }
                Err(c::Error::FlowFailure {
                    cause: _,
                    stages,
                    residual_assessment,
                    ..
                }) if !stages.is_empty() => encode_response(Err(c::Error::FlowFailure {
                    cause: Box::new(c::Error::ResourceLimit),
                    stages,
                    residual_assessment,
                    diagnostics: Vec::new(),
                })),
                _ => Err(ProtocolError::ResourceLimit),
            };
            let frame = compact.or_else(|_| encode_response(Err(c::Error::ResourceLimit)))?;
            if frame.len() <= MAX_BYTES.saturating_sub(used) {
                Ok(frame)
            } else {
                Err(ProtocolError::ResourceLimit)
            }
        }
    }
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
