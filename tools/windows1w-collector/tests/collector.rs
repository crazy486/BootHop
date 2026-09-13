mod support;

use boothop_core::BootId;
use boothop_windows1w_collector::{
    ACKNOWLEDGEMENT, Args, CallError, FirmwareType, PrivilegeState, ReadOutcome, VariableName,
    collect_with, parse_args,
};
use support::{FakeCalls, load_option_bytes};

#[test]
fn firmware_api_failure_and_non_uefi_stop_before_privilege_or_reads() {
    let mut failed = FakeCalls::with_firmware_error(5);
    let result = collect_with(&mut failed);
    assert!(result.is_err());
    assert_eq!(failed.log, ["firmware_type"]);

    let mut bios = FakeCalls::new(FirmwareType::Bios);
    let result = collect_with(&mut bios);
    assert!(result.is_err());
    assert_eq!(bios.log, ["firmware_type"]);
}

#[test]
fn privilege_success_restores_original_state_and_failed_restore_is_terminal() {
    let mut calls = FakeCalls::minimal_valid();
    let result = collect_with(&mut calls).expect("fake collection succeeds");
    assert!(result.accepted);
    assert_eq!(calls.log.last().map(String::as_str), Some("restore"));
    assert_eq!(calls.restored, Some(PrivilegeState { was_enabled: false }));

    let mut failed = FakeCalls::minimal_valid();
    failed.restore_error = Some(CallError::new(87));
    let result = collect_with(&mut failed);
    assert!(result.is_err());
    assert_eq!(failed.log.last().map(String::as_str), Some("restore"));
    assert!(
        !failed
            .log
            .iter()
            .skip_while(|entry| entry != &&"restore".to_string())
            .skip(1)
            .any(|_| true)
    );
}

#[test]
fn attempts_capture_semantic_name_counts_error_attributes_digest_and_bounded_summary() {
    let mut calls = FakeCalls::minimal_valid();
    let evidence = collect_with(&mut calls).expect("fake collection succeeds");
    let boot_order = evidence
        .attempts
        .iter()
        .find(|attempt| attempt.variable == VariableName::BootOrder && attempt.success)
        .expect("BootOrder attempt");
    assert_eq!(boot_order.bytes_returned, 2);
    assert_eq!(boot_order.last_error, 0);
    assert_eq!(boot_order.attributes, 7);
    assert_eq!(boot_order.payload_sha256.len(), 64);
    assert!(boot_order.summary.len() <= 160);
    assert!(evidence.attempts.iter().all(|attempt| attempt.variable
        != VariableName::Boot(BootId(0xffff))
        || attempt.summary.len() <= 160));
}

#[test]
fn failed_read_retains_immediate_raw_error_and_does_not_become_absent() {
    let mut calls = FakeCalls::minimal_valid();
    calls.boot_next = ReadOutcome::failure(2, 7);
    let evidence =
        collect_with(&mut calls).expect("BootNext failure does not abort fake collection");
    let attempt = evidence
        .attempts
        .iter()
        .find(|attempt| attempt.variable == VariableName::BootNext && !attempt.success)
        .expect("failed BootNext attempt");
    assert_eq!(attempt.last_error, 7);
    assert!(!evidence.boot_next_absent);
    assert!(!calls.log.iter().any(|entry| entry == "read Boot0007"));
}

#[test]
fn exact_attributes_are_required_for_each_variable_kind() {
    for (variable, attributes) in [
        (VariableName::BootOrder, 7),
        (VariableName::BootCurrent, 6),
        (VariableName::BootNext, 7),
        (VariableName::Boot(BootId(1)), 7),
    ] {
        let mut calls = FakeCalls::minimal_valid();
        calls.set_attributes(variable, attributes);
        assert!(
            collect_with(&mut calls).is_ok(),
            "{variable:?} with {attributes}"
        );
        for wrong in [0, 1, 6, 8, u32::MAX] {
            if wrong == attributes {
                continue;
            }
            let mut calls = FakeCalls::minimal_valid();
            calls.set_attributes(variable, wrong);
            assert!(
                collect_with(&mut calls).is_err(),
                "{variable:?} with {wrong}"
            );
        }
    }
}

#[test]
fn malformed_controls_fail_closed_and_only_referenced_options_are_read_once_per_pass() {
    let mut calls = FakeCalls::minimal_valid();
    calls.boot_order = ReadOutcome::success(7, vec![1, 0, 1, 0, 2, 0]);
    calls.options.insert(BootId(2), load_option_bytes());
    let evidence = collect_with(&mut calls).expect("deduplicated references succeed");
    assert_eq!(evidence.option_ids, [BootId(1), BootId(2)]);
    assert_eq!(calls.read_count(VariableName::Boot(BootId(1))), 1);
    assert_eq!(calls.read_count(VariableName::Boot(BootId(2))), 1);
    assert!(!calls.log.iter().any(|entry| entry.contains("Boot0000")));

    let mut malformed = FakeCalls::minimal_valid();
    malformed.boot_order = ReadOutcome::success(7, vec![1]);
    assert!(collect_with(&mut malformed).is_err());
}

#[test]
fn bounded_resize_retries_only_buffer_too_small_and_oversize_fails_without_truncated_success() {
    let mut calls = FakeCalls::minimal_valid();
    calls.resize_boot_order = Some(65_537);
    let evidence = collect_with(&mut calls).expect("bounded resize remains within cap");
    assert!(
        evidence
            .attempts
            .iter()
            .any(|a| a.variable == VariableName::BootOrder && a.buffer_too_small)
    );

    let mut too_large = FakeCalls::minimal_valid();
    too_large.resize_boot_order = Some(1_048_577);
    assert!(collect_with(&mut too_large).is_err());
}

#[test]
fn second_control_pass_detects_sequential_instability() {
    let mut calls = FakeCalls::minimal_valid();
    calls.second_order = Some(vec![2, 0]);
    let evidence = collect_with(&mut calls).expect("instability is evidence, not a panic");
    assert!(!evidence.stable);
}

#[test]
fn acknowledgement_and_run_id_validation_are_exact_and_private_path_safe() {
    let valid = parse_args([ACKNOWLEDGEMENT.to_string(), "--run-id=run_01-A".to_string()])
        .expect("valid ordered interlock");
    assert_eq!(
        valid,
        Args {
            run_id: "run_01-A".into()
        }
    );
    let invalid: Vec<Vec<String>> = vec![
        vec!["--run-id=run".into(), ACKNOWLEDGEMENT.into()],
        vec!["--acknowledge=wrong".into(), "--run-id=run".into()],
        vec![ACKNOWLEDGEMENT.into()],
        vec![ACKNOWLEDGEMENT.into(), "--run-id=../x".into()],
        vec![ACKNOWLEDGEMENT.into(), "--run-id=C:root".into()],
        vec![ACKNOWLEDGEMENT.into(), "--run-id=CON.txt".into()],
        vec![ACKNOWLEDGEMENT.into(), "--run-id=".into()],
    ];
    for args in invalid {
        assert!(parse_args(args).is_err(), "unsafe args accepted");
    }
}
