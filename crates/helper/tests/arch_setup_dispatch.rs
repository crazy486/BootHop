#![cfg(target_os = "linux")]

use boothop_helper::arch_setup_cli::{CliError, SetupArgs, dispatch_setup, parse_setup_args};

#[test]
fn setup_requires_explicit_apply() {
    assert!(parse_setup_args(&["--kernel".into(), "linux".into()], 0).is_err());
}

#[test]
fn setup_cli_rejects_non_root_unknown_arguments_and_path_or_id_flavors() {
    let valid = ["--kernel".into(), "linux-lts".into(), "--apply".into()];
    assert_eq!(
        parse_setup_args(&valid, 0),
        Ok(SetupArgs {
            flavor: "linux-lts".into()
        })
    );
    assert_eq!(parse_setup_args(&valid, 1000), Err(CliError::NotRoot));
    for args in [
        vec!["--kernel".into(), "/boot/arch.efi".into(), "--apply".into()],
        vec!["--kernel".into(), "../linux".into(), "--apply".into()],
        vec![
            "--kernel".into(),
            "Boot0001".into(),
            "--apply".into(),
            "--id".into(),
        ],
        vec!["--apply".into(), "--kernel".into(), "linux".into()],
        vec!["--kernel".into(), "linux".into(), "--dry-run".into()],
    ] {
        assert_eq!(parse_setup_args(&args, 0), Err(CliError::Usage), "{args:?}");
    }
}

#[test]
fn setup_dispatch_opens_backend_only_after_root_gate_and_strict_arguments() {
    let valid = ["--kernel".into(), "linux-zen".into(), "--apply".into()];
    let mut opened = Vec::new();
    let nonroot = dispatch_setup(&valid, 1000, |setup| opened.push(setup.flavor));
    assert_eq!(nonroot, Err(CliError::NotRoot));
    assert!(opened.is_empty());

    let invalid = [
        "--kernel".into(),
        "linux-zen".into(),
        "--apply".into(),
        "--force".into(),
    ];
    let invalid_result = dispatch_setup(&invalid, 0, |setup| opened.push(setup.flavor));
    assert_eq!(invalid_result, Err(CliError::Usage));
    assert!(opened.is_empty());

    let valid_result = dispatch_setup(&valid, 0, |setup| {
        opened.push(setup.flavor);
        "dispatched"
    });
    assert_eq!(valid_result, Ok("dispatched"));
    assert_eq!(opened, ["linux-zen"]);
}

#[test]
fn daily_helper_policy_does_not_name_setup_executable() {
    let policy = include_str!("../../../packaging/linux/org.boothop.helper.policy");
    assert!(policy.contains("/usr/lib/boothop/boothop-helper"));
    assert!(!policy.contains("boothop-arch-setup"));
    assert!(!policy.contains("boothop-m4-guest-setup"));
    let daily = include_str!("../src/dispatch.rs");
    assert!(!daily.contains("arch_setup"));
}

#[test]
fn packaged_host_setup_entry_remains_fail_closed() {
    let host_setup = include_str!("../src/bin/boothop-arch-setup.rs");
    assert!(host_setup.contains("Arch direct setup is unavailable"));
    assert!(host_setup.contains("std::process::exit(1)"));
    assert!(!host_setup.contains("NativeArchCalls::open"));
}
