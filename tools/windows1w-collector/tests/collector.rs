mod support;

use boothop_core::BootId;
use boothop_windows1w_collector::{
    ACKNOWLEDGEMENT, CallError, FirmwareType, PrivilegeState, ReadOutcome, ReadStatus,
    TerminalOutcome, VariableName, collect_with, parse_args,
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
    let failure = result.expect_err("restore failure");
    assert!(!failure.evidence.accepted);
    assert_eq!(failure.evidence.terminal, TerminalOutcome::Failed);
    assert!(!failure.evidence.attempts.is_empty());
    assert!(!failure.evidence.options.is_empty());
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
fn privilege_enable_failure_preserves_raw_u32_and_does_not_restore() {
    let mut calls = FakeCalls::minimal_valid();
    calls.enable_error = Some(CallError::new(u32::MAX));
    let failure = collect_with(&mut calls).expect_err("privilege failure");
    assert_eq!(failure.error.raw_code(), Some(u32::MAX));
    assert_eq!(calls.log, ["firmware_type", "enable_privilege"]);
}

#[test]
fn required_read_failure_returns_partial_attempt_evidence_and_terminal_error() {
    let mut calls = FakeCalls::minimal_valid();
    calls.boot_current = ReadOutcome::failure(0, u32::MAX);
    let failure = collect_with(&mut calls).expect_err("required read failure");
    assert_eq!(failure.error.variable(), Some(VariableName::BootCurrent));
    assert_eq!(failure.error.raw_code(), Some(u32::MAX));
    assert!(
        failure
            .evidence
            .attempts
            .iter()
            .any(|a| a.variable == VariableName::BootOrder)
    );
    assert!(
        failure
            .evidence
            .attempts
            .iter()
            .any(|a| a.variable == VariableName::BootCurrent)
    );
    assert!(!failure.evidence.accepted);
    assert_eq!(calls.log.last().map(String::as_str), Some("restore"));
}

#[test]
fn explicit_missing_option_is_distinct_from_other_read_errors() {
    let mut missing = FakeCalls::minimal_valid();
    missing.options.remove(&BootId(1));
    missing.option_status = ReadStatus::Missing;
    let failure = collect_with(&mut missing).expect_err("missing referenced option");
    assert_eq!(failure.error.missing_boot_id(), Some(BootId(1)));
    assert_eq!(failure.error.raw_code(), Some(2));

    let mut error = FakeCalls::minimal_valid();
    error.options.remove(&BootId(1));
    error.option_status = ReadStatus::Error;
    error.option_error = 2;
    let failure = collect_with(&mut error).expect_err("unreadable referenced option");
    assert_eq!(failure.error.missing_boot_id(), None);
    assert_eq!(failure.error.raw_code(), Some(2));
}

#[test]
fn malformed_current_or_next_is_recorded_and_non_accepting() {
    let mut current = FakeCalls::minimal_valid();
    current.boot_current = ReadOutcome::success(6, vec![1]);
    let failure = collect_with(&mut current).expect_err("malformed BootCurrent");
    assert_eq!(failure.error.variable(), Some(VariableName::BootCurrent));

    let mut next = FakeCalls::minimal_valid();
    next.boot_next = ReadOutcome::success(7, vec![1]);
    let failure = collect_with(&mut next).expect_err("malformed BootNext");
    assert_eq!(failure.error.variable(), Some(VariableName::BootNext));
}

#[test]
fn known_sha256_and_failed_bootnext_cannot_be_accepted() {
    let mut calls = FakeCalls::minimal_valid();
    calls.boot_next = ReadOutcome::failure(0, 55);
    let evidence = collect_with(&mut calls).expect("optional failure is retained");
    let attempt = evidence
        .attempts
        .iter()
        .find(|a| a.variable == VariableName::BootOrder && a.success)
        .unwrap();
    assert_eq!(
        attempt.payload_sha256,
        "47dc540c94ceb704a23875c11273e16bb0b8a87aed84de911f2133568115f254"
    );
    assert!(!evidence.accepted);
    assert_eq!(evidence.terminal, TerminalOutcome::BootNextUnavailable);
}

#[test]
fn differing_bootnext_failures_are_unstable_even_without_decoded_values() {
    let mut calls = FakeCalls::minimal_valid();
    calls.boot_next = ReadOutcome::failure(0, 11);
    calls.second_boot_next_error = Some(12);
    let evidence = collect_with(&mut calls).expect("failure observations are evidence");
    assert!(!evidence.stable);
    assert!(!evidence.accepted);
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
    assert_eq!(valid.run_id(), "run_01-A");
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
