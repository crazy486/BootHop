use crate::{MAX_SUMMARY_BYTES, VariableName};
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
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(crate) fn attempt(
    variable: VariableName,
    success: bool,
    bytes_returned: usize,
    last_error: u32,
    attributes: u32,
    bytes: &[u8],
    buffer_too_small: bool,
) -> Attempt {
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
