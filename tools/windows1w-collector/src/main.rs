#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::env;

    use boothop_windows1w_collector::{
        WindowsBackend, collect_with, parse_args, prepare_evidence_path, render_private_report,
        write_option_payloads, write_report,
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
        Ok(evidence) => {
            if let Err(error) = write_option_payloads(&root, &evidence) {
                eprintln!("cannot write private option payloads: {error}");
                return std::process::ExitCode::FAILURE;
            }
            let report = match render_private_report(&evidence, None) {
                Ok(report) => report,
                Err(error) => {
                    eprintln!("cannot render private collector report: {error:?}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            (evidence.accepted, report)
        }
        Err(failure) => {
            if let Err(error) = write_option_payloads(&root, &failure.evidence) {
                eprintln!("cannot write private option payloads: {error}");
                return std::process::ExitCode::FAILURE;
            }
            let error_text = format!("{:?}", failure.error);
            let report = match render_private_report(&failure.evidence, Some(&error_text)) {
                Ok(report) => report,
                Err(error) => {
                    eprintln!("cannot render private collector report: {error:?}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            (false, report)
        }
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
