#![cfg(target_os = "linux")]

use boothop_helper::arch_setup_cli::{CliError, SetupArgs, parse_setup_args};

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
fn daily_helper_policy_does_not_name_setup_executable() {
    let policy = include_str!("../../../packaging/linux/org.boothop.helper.policy");
    assert!(policy.contains("/usr/lib/boothop/boothop-helper"));
    assert!(!policy.contains("boothop-arch-setup"));
    let daily = include_str!("../src/dispatch.rs");
    assert!(!daily.contains("arch_setup"));
}
