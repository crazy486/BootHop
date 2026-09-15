#[path = "support/windows.rs"]
mod windows_support;

use boothop_core::{BootId, Error};
use boothop_platform::windows::{
    FirmwareType, GLOBAL_VARIABLE_GUID, ReadOutcome, VariableName, check_environment, read_next,
    read_options,
};
use windows_support::{FakeWindowsCalls, error, id, install_inventory, order, success};

#[test]
fn environment_accepts_uefi_and_rejects_bios_or_unknown() {
    let mut calls = FakeWindowsCalls::uefi();
    assert_eq!(check_environment(&mut calls), Ok(()));
    for firmware in [FirmwareType::Bios, FirmwareType::Unknown(99)] {
        let mut calls = FakeWindowsCalls::uefi();
        calls.firmware = Ok(firmware);
        assert_eq!(check_environment(&mut calls), Err(Error::NotUefi));
    }
}

#[test]
fn read_options_uses_exact_shapes_and_deduplicated_control_union() {
    let mut calls = FakeWindowsCalls::uefi();
    install_inventory(&mut calls, &[7, 7, 8]);
    calls.set(VariableName::BootOrder, success(7, order(&[7, 7, 8])));
    let inventory = read_options(&mut calls).unwrap();
    assert_eq!(inventory.entries.len(), 2);
    assert_eq!(inventory.entries[0].0, BootId(7));
    assert_eq!(inventory.entries[1].0, BootId(8));
    assert_eq!(calls.read_count(VariableName::BootNext), 0);
}

#[test]
fn read_options_does_not_scan_or_read_boot_next() {
    let mut calls = FakeWindowsCalls::uefi();
    install_inventory(&mut calls, &[7]);
    calls.set(VariableName::BootNext, error(5));
    let result = read_options(&mut calls);
    assert!(result.is_ok());
    assert_eq!(calls.read_count(VariableName::BootNext), 0);
}

#[test]
fn read_next_rejects_unavailable_203_instead_of_treating_it_as_absent() {
    let mut calls = FakeWindowsCalls::uefi();
    calls.set(VariableName::BootNext, ReadOutcome::missing(203));
    assert_eq!(
        read_next(&mut calls),
        Err(Error::BootNextUnavailable { raw_code: 203 })
    );
}

#[test]
fn bounded_reader_grows_from_4k_and_charges_four_attribute_bytes() {
    let mut calls = FakeWindowsCalls::uefi();
    let mut outcome = success(7, vec![0; 8192]);
    outcome.buffer_too_small = true;
    outcome.required_size = 8192;
    calls.script(
        VariableName::BootNext,
        vec![outcome, success(7, id(0x1234))],
    );
    assert_eq!(read_next(&mut calls), Ok(Some(BootId(0x1234))));
    assert_eq!(calls.reads[0], (VariableName::BootNext, 4096));
    assert_eq!(calls.reads[1], (VariableName::BootNext, 8192));
}

#[test]
fn malformed_controls_and_referenced_options_fail_closed() {
    let mut calls = FakeWindowsCalls::uefi();
    install_inventory(&mut calls, &[7]);
    calls.set(VariableName::BootOrder, success(7, vec![7]));
    assert_eq!(read_options(&mut calls), Err(Error::UnsupportedFormat));

    let mut calls = FakeWindowsCalls::uefi();
    install_inventory(&mut calls, &[7]);
    calls.set(VariableName::Boot(BootId(7)), error(5));
    assert_eq!(
        read_options(&mut calls),
        Err(Error::FirmwareReadFailed { raw_code: 5 })
    );
}

#[test]
fn all_control_attributes_and_payload_shapes_are_checked() {
    for (variable, attributes, bytes) in [
        (VariableName::BootOrder, 6, order(&[7])),
        (VariableName::BootCurrent, 7, id(7)),
        (VariableName::BootNext, 6, id(7)),
    ] {
        let mut calls = FakeWindowsCalls::uefi();
        install_inventory(&mut calls, &[7]);
        calls.set(variable, success(attributes, bytes));
        let result = if variable == VariableName::BootNext {
            read_next(&mut calls).map(|_| ())
        } else {
            read_options(&mut calls).map(|_| ())
        };
        assert_eq!(result, Err(Error::UnsupportedFormat));
    }

    let mut calls = FakeWindowsCalls::uefi();
    install_inventory(&mut calls, &[7]);
    calls.set(VariableName::BootCurrent, success(6, vec![7]));
    assert_eq!(read_options(&mut calls), Err(Error::UnsupportedFormat));

    let mut calls = FakeWindowsCalls::uefi();
    calls.set(VariableName::BootNext, success(7, vec![7]));
    assert_eq!(read_next(&mut calls), Err(Error::UnsupportedFormat));
}

#[test]
fn raw_budget_charges_attributes_per_variable_and_cumulatively() {
    let mut calls = FakeWindowsCalls::uefi();
    install_inventory(&mut calls, &[7]);
    let mut option = windows_support::option_payload();
    option.resize(1_048_560, 0);
    calls.script(
        VariableName::Boot(BootId(7)),
        vec![
            ReadOutcome::buffer_too_small(option.len(), 7),
            success(7, option.clone()),
        ],
    );
    assert!(read_options(&mut calls).is_ok());
    option.push(0);
    let mut calls = FakeWindowsCalls::uefi();
    install_inventory(&mut calls, &[7]);
    calls.script(
        VariableName::Boot(BootId(7)),
        vec![
            ReadOutcome::buffer_too_small(option.len(), 7),
            success(7, option),
        ],
    );
    assert_eq!(read_options(&mut calls), Err(Error::ResourceLimit));

    let mut calls = FakeWindowsCalls::uefi();
    calls.set(VariableName::BootNext, success(7, vec![0; 1_048_573]));
    assert_eq!(read_next(&mut calls), Err(Error::ResourceLimit));
}

#[test]
fn raw_firmware_errors_are_immediate_and_preserve_codes() {
    let mut calls = FakeWindowsCalls::uefi();
    calls.set(VariableName::BootNext, error(203));
    assert_eq!(
        read_next(&mut calls),
        Err(Error::FirmwareReadFailed { raw_code: 203 })
    );
    let mut calls = FakeWindowsCalls::uefi();
    calls.firmware = Err(boothop_platform::windows::CallError::new(55));
    assert_eq!(
        check_environment(&mut calls),
        Err(Error::FirmwareReadFailed { raw_code: 55 })
    );
}

#[test]
fn production_uses_one_exact_global_variable_guid() {
    assert_eq!(
        GLOBAL_VARIABLE_GUID,
        "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
    );
}

#[test]
fn successful_result_larger_than_requested_buffer_is_rejected() {
    let mut calls = FakeWindowsCalls::uefi();
    calls.set(
        VariableName::BootNext,
        ReadOutcome::success(7, vec![0; 4097]),
    );
    assert_eq!(read_next(&mut calls), Err(Error::ResourceLimit));
}

#[test]
fn growth_reaches_one_mib_and_oversize_transition_fails() {
    let mut calls = FakeWindowsCalls::uefi();
    let mut script = Vec::new();
    let mut size = 4096;
    while size < 1_048_576 {
        size *= 2;
        script.push(ReadOutcome::buffer_too_small(size, 7));
    }
    script.push(success(7, id(7)));
    calls.script(VariableName::BootNext, script);
    assert_eq!(read_next(&mut calls), Ok(Some(BootId(7))));
    assert_eq!(
        calls.reads.last(),
        Some(&(VariableName::BootNext, 1_048_576))
    );

    let mut calls = FakeWindowsCalls::uefi();
    calls.set(
        VariableName::BootNext,
        ReadOutcome::buffer_too_small(1_048_577, 7),
    );
    assert_eq!(read_next(&mut calls), Err(Error::ResourceLimit));
}
