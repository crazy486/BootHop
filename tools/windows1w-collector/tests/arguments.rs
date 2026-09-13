use std::path::Path;

#[cfg(windows)]
use boothop_windows1w_collector::WindowsBackend;
use boothop_windows1w_collector::{
    ACKNOWLEDGEMENT, ArgumentError, WindowsCalls, evidence_path, parse_args,
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

#[cfg(windows)]
#[test]
fn backend_compile_check_never_constructs_or_runs_it() {
    fn assert_backend_implements_boundary<C: WindowsCalls>() {}
    assert_backend_implements_boundary::<WindowsBackend>();
}
