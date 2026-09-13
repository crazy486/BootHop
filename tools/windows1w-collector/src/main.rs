#[cfg(windows)]
fn main() {
    use std::env;
    use std::fs;

    use boothop_windows1w_collector::{WindowsBackend, collect_with, evidence_path, parse_args};

    let raw_args: Vec<String> = env::args().skip(1).collect();
    let args = match parse_args(raw_args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("invalid collector arguments: {error:?}");
            return;
        }
    };
    let root = match evidence_path(&args) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("invalid evidence path: {error:?}");
            return;
        }
    };
    if let Err(error) = fs::create_dir_all(&root) {
        eprintln!("cannot create private evidence directory: {error}");
        return;
    }

    let mut calls = WindowsBackend::new();
    let report = match collect_with(&mut calls) {
        Ok(evidence) => format!("{evidence:#?}\n"),
        Err(failure) => format!("{failure:#?}\n"),
    };
    if let Err(error) = fs::write(root.join("collector-report.txt"), report) {
        eprintln!("cannot write private collector report: {error}");
    }
}

#[cfg(not(windows))]
fn main() {
    // The release artifact is targeted at Windows. This host-only stub keeps
    // workspace metadata and ordinary library tests buildable without ever
    // constructing the native backend.
}
