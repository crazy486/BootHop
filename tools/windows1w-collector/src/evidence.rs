use crate::{MAX_SUMMARY_BYTES, ReadStatus, VariableName};
use boothop_core::{BootId, LoadOption};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    pub variable: VariableName,
    pub success: bool,
    pub bytes_returned: usize,
    pub last_error: u32,
    pub attributes: u32,
    pub payload_sha256: String,
    pub summary: String,
    pub buffer_too_small: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalOutcome {
    Accepted,
    BootNextUnavailable,
    Unstable,
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptionEvidence {
    pub boot_id: BootId,
    pub raw_payload: Vec<u8>,
    pub parsed: LoadOption,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub attempts: Vec<Attempt>,
    pub options: Vec<OptionEvidence>,
    pub option_ids: Vec<BootId>,
    pub stable: bool,
    pub accepted: bool,
    pub boot_next_absent: bool,
    pub terminal: TerminalOutcome,
}

impl Evidence {
    pub(crate) fn failed(attempts: Vec<Attempt>) -> Self {
        Self {
            attempts,
            options: Vec::new(),
            option_ids: Vec::new(),
            stable: false,
            accepted: false,
            boot_next_absent: false,
            terminal: TerminalOutcome::Failed,
        }
    }
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(crate) fn attempt(
    variable: VariableName,
    status: ReadStatus,
    bytes_returned: usize,
    last_error: u32,
    attributes: u32,
    bytes: &[u8],
    buffer_too_small: bool,
) -> Attempt {
    let success = status == ReadStatus::Success;
    let mut summary = if buffer_too_small {
        format!("{variable}: buffer-too-small")
    } else if success {
        format!("{variable}: success, {bytes_returned} bytes")
    } else {
        format!("{variable}: failure, error {last_error}")
    };
    summary.truncate(MAX_SUMMARY_BYTES);
    Attempt {
        variable,
        success,
        bytes_returned,
        last_error,
        attributes,
        payload_sha256: digest(bytes),
        summary,
        buffer_too_small,
    }
}
