#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::env;

    use boothop_windows1w_collector::{
        WindowsBackend, collect_with, parse_args, prepare_evidence_path, write_report,
    };

    let raw_args: Vec<String> = env::args().skip(1).collect();
    let args = match parse_args(raw_args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("invalid collector arguments: {error:?}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let root = match prepare_evidence_path(&args) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("invalid evidence path: {error:?}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut calls = WindowsBackend::new();
    let (accepted, report) = match collect_with(&mut calls) {
        Ok(evidence) => (evidence.accepted, render_evidence(&evidence)),
        Err(failure) => (false, render_failure(&failure)),
    };
    if let Err(error) = write_report(&root.join("collector-report.txt"), &report) {
        eprintln!("cannot write private collector report: {error}");
        return std::process::ExitCode::FAILURE;
    }
    if accepted {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    // The release artifact is targeted at Windows. This host-only stub keeps
    // workspace metadata and ordinary library tests buildable without ever
    // constructing the native backend.
    std::process::ExitCode::FAILURE
}

#[cfg(windows)]
fn render_evidence(evidence: &boothop_windows1w_collector::Evidence) -> String {
    format!(
        "accepted={} terminal={:?} stable={} attempts={} options={} option_ids={:?}\n",
        evidence.accepted,
        evidence.terminal,
        evidence.stable,
        evidence.attempts.len(),
        evidence.options.len(),
        evidence.option_ids,
    )
}

#[cfg(windows)]
fn render_failure(failure: &boothop_windows1w_collector::CollectionFailure) -> String {
    format!(
        "accepted=false error={:?} attempts={} options={} option_ids={:?}\n",
        failure.error,
        failure.evidence.attempts.len(),
        failure.evidence.options.len(),
        failure.evidence.option_ids,
    )
}
