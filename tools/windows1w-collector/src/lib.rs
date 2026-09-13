mod collect;
mod evidence;
mod model;
#[cfg(windows)]
mod windows;

use std::path::PathBuf;

pub use collect::{CollectionFailure, CollectorError, collect_with};
pub use evidence::{Attempt, Evidence, OptionEvidence, TerminalOutcome};
pub use model::{
    Args, CallError, FirmwareType, INITIAL_BUFFER_BYTES, MAX_PAYLOAD_BYTES, MAX_SUMMARY_BYTES,
    PrivilegeState, ReadOutcome, ReadStatus, VariableName, WindowsCalls,
};
#[cfg(windows)]
pub use windows::WindowsBackend;

pub const ACKNOWLEDGEMENT: &str = "--acknowledge=WINDOWS1W_NATIVE_READ_ONLY_AUTHORIZED";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgumentError {
    WrongShape,
    InvalidAcknowledgement,
    InvalidRunId,
}

pub fn parse_args<I, S>(args: I) -> Result<Args, ArgumentError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect();
    if args.len() != 2 {
        return Err(ArgumentError::WrongShape);
    }
    if args[0] != ACKNOWLEDGEMENT {
        return Err(ArgumentError::InvalidAcknowledgement);
    }
    let Some(run_id) = args[1].strip_prefix("--run-id=") else {
        return Err(ArgumentError::WrongShape);
    };
    validate_run_id(run_id)?;
    Ok(Args::new(run_id.to_owned()))
}

pub fn evidence_path(args: &Args) -> Result<PathBuf, ArgumentError> {
    validate_run_id(args.run_id())?;
    Ok(PathBuf::from(".superpowers/sdd/2026-09-08-boothop/private/windows1w").join(args.run_id()))
}

fn validate_run_id(run_id: &str) -> Result<(), ArgumentError> {
    if run_id.is_empty() || run_id.len() > 64 || run_id == "." || run_id == ".." {
        return Err(ArgumentError::InvalidRunId);
    }
    let bytes = run_id.as_bytes();
    if !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ArgumentError::InvalidRunId);
    }
    let stem = run_id
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
    {
        return Err(ArgumentError::InvalidRunId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forged_args_cannot_escape_private_evidence_root() {
        let forged = Args::forged_for_test("..\\escape");
        assert_eq!(evidence_path(&forged), Err(ArgumentError::InvalidRunId));
    }
}
