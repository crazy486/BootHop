use std::fs;
use std::path::Path;

#[cfg(windows)]
use boothop_windows1w_collector::WindowsBackend;
use boothop_windows1w_collector::{
    ACKNOWLEDGEMENT, ArgumentError, MAX_ENUMERATION_BYTES, WindowsCalls, evidence_path, parse_args,
    write_report,
};

#[test]
fn parser_requires_the_exact_ordered_interlock() {
    let args = parse_args([ACKNOWLEDGEMENT, "--run-id=accepted.run_01"])
        .expect("the exact two-argument interlock is accepted");
    assert_eq!(args.run_id(), "accepted.run_01");

    for rejected in [
        vec!["--run-id=accepted", ACKNOWLEDGEMENT],
        vec![ACKNOWLEDGEMENT, "--run-id=accepted", "extra"],
        vec![
            "--acknowledge=WINDOWS1W_NATIVE_READ_ONLY_AUTHORIZED ",
            "--run-id=accepted",
        ],
        vec![ACKNOWLEDGEMENT, "--run-id=ACCEPTED/escape"],
    ] {
        assert!(
            parse_args(rejected).is_err(),
            "unsafe argument shape accepted"
        );
    }
}

#[test]
fn run_id_validation_rejects_windows_devices_and_path_syntax() {
    for name in [
        "",
        ".",
        "..",
        "CON",
        "con.txt",
        "PRN.log",
        "AUX.foo",
        "NUL.bin",
        "COM1",
        "COM9.txt",
        "LPT1",
        "LPT9.log",
        "C:run",
        "C:\\run",
        "\\\\server\\share",
        "../run",
        "run/child",
        "run\\child",
        "run.",
    ] {
        let argument = format!("--run-id={name}");
        assert_eq!(
            parse_args([ACKNOWLEDGEMENT, &argument]),
            Err(ArgumentError::InvalidRunId),
            "unsafe run id accepted: {name:?}"
        );
    }

    for name in ["r", "run_01-A", "r.with.dots", "a-123"] {
        let argument = format!("--run-id={name}");
        let args = parse_args([ACKNOWLEDGEMENT, &argument]).expect("safe run id");
        let path = evidence_path(&args).expect("safe evidence path");
        assert_eq!(
            path,
            Path::new(".superpowers/sdd/2026-09-08-boothop/private/windows1w").join(name)
        );
    }
}

#[test]
fn backend_source_uses_the_braced_fixed_firmware_guid() {
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/windows.rs"))
        .expect("Windows backend source");
    assert!(
        source.contains("const FIRMWARE_GUID: &str = \"{8be4df61-93ca-11d2-aa0d-00e098032b8c}\";")
    );
    assert!(source.contains("SetLastError(0)"));
    assert!(source.contains("previous.PrivilegeCount == 0"));
    assert!(source.contains("impl Drop for WindowsBackend"));
    assert_eq!(MAX_ENUMERATION_BYTES, 1_048_576);
}

#[test]
fn entrypoint_uses_exit_codes_and_exclusive_bounded_report_writes() {
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .expect("entry point source");
    let library = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("library source");
    assert!(source.contains("ExitCode"));
    assert!(source.contains("ExitCode::FAILURE"));
    assert!(library.contains("create_new(true)"));
}

#[test]
fn report_creation_is_exclusive_and_bounded() {
    let directory = std::env::temp_dir().join(format!(
        "boothop-windows1w-collector-test-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).expect("test directory");
    let report = directory.join("collector-report.txt");
    write_report(&report, "accepted=true\n").expect("first report write");
    assert!(write_report(&report, "overwrite\n").is_err());
    let oversized = "x".repeat(128 * 1024);
    assert!(write_report(&directory.join("large.txt"), &oversized).is_err());
    fs::remove_dir_all(directory).expect("remove test directory");
}

#[test]
fn evidence_path_hardening_uses_no_follow_checks_and_containment() {
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("library source");
    assert!(source.contains("symlink_metadata"));
    assert!(source.contains("canonicalize"));
    assert!(source.contains("starts_with"));
    assert!(source.contains("create_new(true)"));
}

#[cfg(windows)]
#[test]
fn backend_compile_check_never_constructs_or_runs_it() {
    fn assert_backend_implements_boundary<C: WindowsCalls>() {}
    assert_backend_implements_boundary::<WindowsBackend>();
}
