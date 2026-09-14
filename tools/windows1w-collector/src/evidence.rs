use crate::{MAX_REPORT_BYTES, MAX_SUMMARY_BYTES, ReadStatus, VariableName};
use boothop_core::{BootId, LoadOption};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    pub variable: VariableName,
    pub status: ReadStatus,
    pub success: bool,
    pub bytes_returned: usize,
    pub last_error: u32,
    pub attributes: u32,
    pub payload_sha256: String,
    pub summary: String,
    pub buffer_too_small: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlValue {
    pub status: ReadStatus,
    pub value: Option<BootId>,
    pub bytes_returned: usize,
    pub last_error: u32,
    pub attributes: u32,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlSnapshot {
    pub boot_order: Vec<BootId>,
    pub boot_order_status: ReadStatus,
    pub boot_order_bytes_returned: usize,
    pub boot_order_last_error: u32,
    pub boot_order_attributes: u32,
    pub boot_order_payload_sha256: String,
    pub boot_current: ControlValue,
    pub boot_next: ControlValue,
    pub sequential_not_atomic: bool,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawOptionValidation {
    Valid,
    InvalidAttributes { expected: u32, actual: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawOptionParseStatus {
    NotAttempted,
    Valid,
    Malformed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawOptionEvidence {
    pub boot_id: BootId,
    pub raw_payload: Vec<u8>,
    pub status: ReadStatus,
    pub attributes: u32,
    pub validation: RawOptionValidation,
    pub parse_status: RawOptionParseStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub attempts: Vec<Attempt>,
    pub options: Vec<OptionEvidence>,
    pub raw_options: Vec<RawOptionEvidence>,
    pub option_ids: Vec<BootId>,
    pub stable: bool,
    pub accepted: bool,
    pub boot_next_absent: bool,
    pub terminal: TerminalOutcome,
    pub first_control: Option<Box<ControlSnapshot>>,
    pub second_control: Option<Box<ControlSnapshot>>,
}

impl Evidence {
    pub(crate) fn failed(attempts: Vec<Attempt>) -> Self {
        Self {
            attempts,
            options: Vec::new(),
            raw_options: Vec::new(),
            option_ids: Vec::new(),
            stable: false,
            accepted: false,
            boot_next_absent: false,
            terminal: TerminalOutcome::Failed,
            first_control: None,
            second_control: None,
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
        status,
        success,
        bytes_returned,
        last_error,
        attributes,
        payload_sha256: digest(bytes),
        summary,
        buffer_too_small,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportError {
    TooLarge,
}

pub fn render_private_report(
    evidence: &Evidence,
    error: Option<&str>,
) -> Result<String, ReportError> {
    let mut report = String::new();
    push_line(&mut report, "format=windows1w-sequential-v1")?;
    push_line(&mut report, "snapshot_semantics=sequential_not_atomic")?;
    if let Some(error) = error {
        push_line(&mut report, &format!("error={error}"))?;
    }
    push_line(
        &mut report,
        &format!(
            "accepted={} terminal={:?} stable={} boot_next_absent={}",
            evidence.accepted, evidence.terminal, evidence.stable, evidence.boot_next_absent
        ),
    )?;
    for (ordinal, attempt) in evidence.attempts.iter().enumerate() {
        push_line(
            &mut report,
            &format!(
                "attempt ordinal={} variable={} status={:?} success={} bytes_returned={} last_error={} attributes={} payload_sha256={} summary={:?} buffer_too_small={}",
                ordinal,
                attempt.variable,
                attempt.status,
                attempt.success,
                attempt.bytes_returned,
                attempt.last_error,
                attempt.attributes,
                attempt.payload_sha256,
                attempt.summary,
                attempt.buffer_too_small,
            ),
        )?;
    }
    for (label, snapshot) in [
        ("first_control", evidence.first_control.as_ref()),
        ("second_control", evidence.second_control.as_ref()),
    ] {
        if let Some(snapshot) = snapshot {
            push_line(
                &mut report,
                &format!(
                    "{} boot_order={:?} boot_order_status={:?} boot_order_bytes_returned={} boot_order_last_error={} boot_order_attributes={} boot_order_payload_sha256={}",
                    label,
                    snapshot.boot_order,
                    snapshot.boot_order_status,
                    snapshot.boot_order_bytes_returned,
                    snapshot.boot_order_last_error,
                    snapshot.boot_order_attributes,
                    snapshot.boot_order_payload_sha256,
                ),
            )?;
            push_value(
                &mut report,
                &format!("{label}.boot_current"),
                &snapshot.boot_current,
            )?;
            push_value(
                &mut report,
                &format!("{label}.boot_next"),
                &snapshot.boot_next,
            )?;
        }
    }
    for raw in &evidence.raw_options {
        push_line(
            &mut report,
            &format!(
                "option boot_id={} raw_file=Boot{:04X}.bin raw_length={} raw_sha256={} status={:?} attributes={} validation={:?} parse_status={:?}",
                raw.boot_id.0,
                raw.boot_id.0,
                raw.raw_payload.len(),
                digest(&raw.raw_payload),
                raw.status,
                raw.attributes,
                raw.validation,
                raw.parse_status,
            ),
        )?;
    }
    Ok(report)
}

fn push_value(report: &mut String, label: &str, value: &ControlValue) -> Result<(), ReportError> {
    push_line(
        report,
        &format!(
            "{} status={:?} value={:?} bytes_returned={} last_error={} attributes={} payload_sha256={}",
            label,
            value.status,
            value.value,
            value.bytes_returned,
            value.last_error,
            value.attributes,
            value.payload_sha256,
        ),
    )
}

fn push_line(report: &mut String, line: &str) -> Result<(), ReportError> {
    if report.len().saturating_add(line.len()).saturating_add(1) > MAX_REPORT_BYTES {
        return Err(ReportError::TooLarge);
    }
    let _ = writeln!(report, "{line}");
    Ok(())
}
