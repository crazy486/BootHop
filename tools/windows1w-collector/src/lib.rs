mod collect;
mod evidence;
mod model;
#[cfg(windows)]
mod windows;

use std::path::PathBuf;
use std::{fs, io, path::Path};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

pub use collect::{CollectionFailure, CollectorError, collect_with};
pub use evidence::{
    Attempt, Evidence, OptionEvidence, RawOptionEvidence, RawOptionParseStatus,
    RawOptionValidation, TerminalOutcome,
};
pub use evidence::{ControlSnapshot, ControlValue, ReportError, render_private_report};
pub use model::{
    Args, CallError, FirmwareType, INITIAL_BUFFER_BYTES, MAX_ENUMERATION_BYTES, MAX_PAYLOAD_BYTES,
    MAX_SUMMARY_BYTES, PrivilegeState, ReadOutcome, ReadStatus, VariableName, WindowsCalls,
};
#[cfg(windows)]
pub use windows::WindowsBackend;

pub const ACKNOWLEDGEMENT: &str = "--acknowledge=WINDOWS1W_NATIVE_READ_ONLY_AUTHORIZED";
const PRIVATE_EVIDENCE_ROOT: &str = ".superpowers/sdd/2026-09-08-boothop/private/windows1w";
pub const MAX_REPORT_BYTES: usize = 64 * 1024;

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

/// Returns the deterministic path for pure inspection/tests only.
///
/// Callers that will create or write evidence must use
/// [`prepare_evidence_path`], which performs fixed-root no-follow checks and
/// canonical containment verification before returning a write path.
pub fn evidence_path(args: &Args) -> Result<PathBuf, ArgumentError> {
    validate_run_id(args.run_id())?;
    Ok(PathBuf::from(".superpowers/sdd/2026-09-08-boothop/private/windows1w").join(args.run_id()))
}

#[derive(Debug)]
pub enum EvidencePathError {
    InvalidRunId,
    Io(io::Error),
    SymlinkOrReparse,
    NotDirectory,
    NotContained,
}

pub fn prepare_evidence_path(args: &Args) -> Result<PathBuf, EvidencePathError> {
    validate_run_id(args.run_id()).map_err(|_| EvidencePathError::InvalidRunId)?;
    let root = PathBuf::from(PRIVATE_EVIDENCE_ROOT);
    ensure_directory_chain(&root)?;
    let run_dir = root.join(args.run_id());
    ensure_directory(&run_dir)?;
    let canonical_root = fs::canonicalize(&root).map_err(EvidencePathError::Io)?;
    let canonical_run = fs::canonicalize(&run_dir).map_err(EvidencePathError::Io)?;
    if !canonical_run.starts_with(&canonical_root) {
        return Err(EvidencePathError::NotContained);
    }
    Ok(canonical_run)
}

pub fn write_report(path: &Path, report: &str) -> io::Result<()> {
    if report.len() > MAX_REPORT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "collector report exceeds the fixed private limit",
        ));
    }
    write_exclusive(path, report.as_bytes(), MAX_REPORT_BYTES)
}

pub fn write_option_payloads(root: &Path, evidence: &Evidence) -> io::Result<()> {
    for option in &evidence.raw_options {
        let path = root.join(format!("Boot{:04X}.bin", option.boot_id.0));
        write_exclusive(&path, &option.raw_payload, MAX_PAYLOAD_BYTES)?;
    }
    Ok(())
}

fn write_exclusive(path: &Path, bytes: &[u8], limit: usize) -> io::Result<()> {
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private evidence payload exceeds the fixed limit",
        ));
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    use io::Write;
    file.write_all(bytes)?;
    file.sync_all()
}

fn ensure_directory_chain(path: &Path) -> Result<(), EvidencePathError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        ensure_directory(&current)?;
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), EvidencePathError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(EvidencePathError::SymlinkOrReparse);
            }
            if !metadata.is_dir() {
                return Err(EvidencePathError::NotDirectory);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(EvidencePathError::Io)?;
            let metadata = fs::symlink_metadata(path).map_err(EvidencePathError::Io)?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(EvidencePathError::SymlinkOrReparse);
            }
            if !metadata.is_dir() {
                return Err(EvidencePathError::NotDirectory);
            }
        }
        Err(error) => return Err(EvidencePathError::Io(error)),
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn validate_run_id(run_id: &str) -> Result<(), ArgumentError> {
    if run_id.is_empty()
        || run_id.len() > 64
        || run_id == "."
        || run_id == ".."
        || run_id.ends_with('.')
    {
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
