mod support;

use boothop_core::{
    BootId, CanonicalDevicePathNode, Classification, DevicePathNodeKind, Error, Os,
    PlatformOperation, RebootOutcome, RecordDiagnostic, RecordState, Request, ResidualAssessment,
    RollbackAssessment, RollbackOutcome, Stage, canonicalize, decode_record, encode_record,
    execute,
};
use support::{Event, FakePlatform};

fn requests() -> [Request; 3] {
    [
        Request::Inspect,
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows,
        },
        Request::Switch { os: Os::Windows },
    ]
}

#[test]
fn rejected_reboot_rolls_back_only_a_write_made_by_core() {
    let mut p = FakePlatform::ready();
    p.reboot_outcome = RebootOutcome::Rejected;
    p.next_reads = [Ok(None), Ok(None), Ok(Some(BootId(7))), Ok(Some(BootId(7)))].into();
    p.rollback_outcome = RollbackOutcome::Restored;

    let Error::FlowFailure {
        cause,
        stages,
        rollback_assessment,
        residual_assessment,
        ..
    } = execute(Request::Switch { os: Os::Windows }, Os::Linux, &mut p).unwrap_err()
    else {
        panic!("expected flow failure")
    };
    assert_eq!(*cause, Error::RebootRejected);
    assert_eq!(rollback_assessment, RollbackAssessment::Restored);
    assert_eq!(
        residual_assessment,
        ResidualAssessment::Observed(Some(BootId(7)))
    );
    assert_eq!(p.next, None);
    assert_eq!(
        stages,
        [
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootRejected,
            Stage::RollbackAttempted,
            Stage::RollbackRestored,
        ]
    );
    assert!(
        p.events
            .iter()
            .any(|event| matches!(event, Event::RollbackNext { .. }))
    );
}

// Removing the initial trusted record read must fail these three-operation checks.
#[test]
fn unknown_record_version_stops() {
    for request in requests() {
        let mut p = FakePlatform::unsupported_version(999);
        assert_eq!(
            execute(request, Os::Linux, &mut p),
            Err(Error::UnsupportedRecordVersion { found: 999 })
        );
        assert_eq!(p.events, [Event::ReadRecord]);
        assert!(!p.events.iter().any(Event::is_mutation));
    }
}

#[test]
fn unknown_identity_component_stops() {
    for request in requests() {
        let mut p = FakePlatform::missing();
        p.record = Err(Error::UnsupportedIdentityComponent);
        assert_eq!(
            execute(request, Os::Linux, &mut p),
            Err(Error::UnsupportedIdentityComponent)
        );
        assert_eq!(p.events, [Event::ReadRecord]);
    }
}

#[test]
fn corrupt_record_is_not_missing() {
    for request in requests() {
        let mut p = FakePlatform::missing();
        p.record = Err(Error::CorruptRecord);
        assert_eq!(
            execute(request, Os::Linux, &mut p),
            Err(Error::CorruptRecord)
        );
        assert!(!p.events.iter().any(Event::is_mutation));
    }
}

#[test]
fn three_inspects_are_read_only() {
    let mut p = FakePlatform::ready();
    let saved = p.record.clone();
    for _ in 0..3 {
        let report = execute(Request::Inspect, Os::Linux, &mut p).unwrap();
        assert_eq!(
            report.record,
            RecordDiagnostic::Ready {
                boot_id: BootId(7),
                os: Os::Windows
            }
        );
        assert!(report.stages.is_empty());
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].boot_id, BootId(7));
        assert_eq!(
            report.candidates[0].classification,
            Classification::NeedsConfirmation
        );
        assert!(!report.candidates[0].ambiguous);
    }
    assert_eq!(p.record, saved);
    assert!(!p.events.iter().any(Event::is_mutation));
}

// This catches the production change that makes an exact saved/live identity match a
// prerequisite for an Inspect Ready report.
#[test]
fn inspect_ready_requires_exact_live_identity_and_has_no_stages() {
    let mut p = FakePlatform::ready();
    let report = execute(Request::Inspect, Os::Linux, &mut p).unwrap();
    assert_eq!(
        report.record,
        RecordDiagnostic::Ready {
            boot_id: BootId(7),
            os: Os::Windows
        }
    );
    assert!(report.stages.is_empty());
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions
        ]
    );
}

// This catches the production change that maps a saved BootId with no live option to
// TargetMissing during Inspect.
#[test]
fn inspect_ready_with_absent_saved_boot_id_returns_target_missing() {
    let mut p = FakePlatform::ready();
    p.options[0].0 = BootId(8);
    assert_eq!(
        execute(Request::Inspect, Os::Linux, &mut p),
        Err(Error::TargetMissing)
    );
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions
        ]
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

// This catches the production change that rejects a changed structured canonical field
// before Inspect can claim the protected target is Ready.
#[test]
fn inspect_ready_with_structured_identity_change_returns_identity_mismatch() {
    let mut p = FakePlatform::ready();
    let node = &mut p.options[0].1.file_paths[0].instances[0].nodes[0];
    let DevicePathNodeKind::HardDrive(hard_drive) = &mut node.kind else {
        panic!("fixture has a hard-drive node")
    };
    hard_drive.partition_number += 1;
    node.payload[0..4].copy_from_slice(&hard_drive.partition_number.to_le_bytes());
    assert_eq!(
        execute(Request::Inspect, Os::Linux, &mut p),
        Err(Error::IdentityMismatch)
    );
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions
        ]
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

// This catches the production change that compares OptionalData OpaqueExact byte length.
#[test]
fn inspect_ready_with_optional_data_length_change_returns_identity_mismatch() {
    let mut p = FakePlatform::ready();
    p.options[0].1.optional_data.push(0);
    assert_eq!(
        execute(Request::Inspect, Os::Linux, &mut p),
        Err(Error::IdentityMismatch)
    );
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions
        ]
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

// This catches the production change that compares OptionalData OpaqueExact content digest.
#[test]
fn inspect_ready_with_equal_length_optional_data_change_returns_identity_mismatch() {
    let mut p = FakePlatform::ready();
    p.options[0].1.optional_data[0] ^= 1;
    assert_eq!(
        execute(Request::Inspect, Os::Linux, &mut p),
        Err(Error::IdentityMismatch)
    );
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions
        ]
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

// This catches the production change that keeps non-identity descriptions out of the
// protected identity comparison.
#[test]
fn inspect_ready_with_description_only_change_remains_ready() {
    let mut p = FakePlatform::ready();
    p.options[0].1.description_utf16 = "Renamed".encode_utf16().collect();
    let report = execute(Request::Inspect, Os::Linux, &mut p).unwrap();
    assert_eq!(
        report.record,
        RecordDiagnostic::Ready {
            boot_id: BootId(7),
            os: Os::Windows
        }
    );
    assert!(report.stages.is_empty());
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions
        ]
    );
}

// This catches the production change that preserves discovery Inspect behavior when no
// protected record exists.
#[test]
fn inspect_missing_record_preserves_discovery_result() {
    let mut p = FakePlatform::missing();
    let report = execute(Request::Inspect, Os::Linux, &mut p).unwrap();
    assert_eq!(report.record, RecordDiagnostic::Missing);
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].boot_id, BootId(7));
    assert_eq!(
        report.candidates[0].classification,
        Classification::NeedsConfirmation
    );
    assert!(report.stages.is_empty());
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions
        ]
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

#[test]
fn unique_name_is_not_known_os() {
    let mut p = FakePlatform::missing();
    p.options[0].1.description_utf16 = "Windows Boot Manager".encode_utf16().collect();
    let report = execute(Request::Inspect, Os::Linux, &mut p).unwrap();
    assert_eq!(report.record, RecordDiagnostic::Missing);
    assert_eq!(
        report.candidates[0].classification,
        Classification::NeedsConfirmation
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

#[test]
fn duplicate_identity_requires_selection() {
    let mut p = FakePlatform::missing();
    p.options.push((BootId(8), p.options[0].1.clone()));
    let report = execute(Request::Inspect, Os::Linux, &mut p).unwrap();
    assert!(report.candidates.iter().all(|c| c.ambiguous));
    assert!(!p.events.iter().any(Event::is_mutation));
    execute(
        Request::Configure {
            boot_id: BootId(8),
            os: Os::Windows,
        },
        Os::Linux,
        &mut p,
    )
    .unwrap();
    let Ok(RecordState::Ready(saved)) = &p.record else {
        panic!("explicit selection saves")
    };
    assert_eq!(saved.boot_id, BootId(8));
}

#[test]
fn confirmed_os_with_valid_target_configures() {
    let mut p = FakePlatform::missing();
    let report = execute(requests()[1], Os::Linux, &mut p).unwrap();
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions,
            Event::SaveRecord
        ]
    );
    assert_eq!(report.stages, [Stage::TargetValidated]);
    assert_eq!(
        report.record,
        RecordDiagnostic::Ready {
            boot_id: BootId(7),
            os: Os::Windows
        }
    );
    let Ok(RecordState::Ready(saved)) = p.record else {
        panic!("configuration saved")
    };
    assert_eq!(saved.identity.optional_data.byte_length, 4);
    assert_eq!(saved.os, Os::Windows);
    assert_eq!(saved.boot_id, BootId(7));
}

#[test]
fn configure_rejects_host_os_and_missing_selected_id() {
    for (request, expected) in [
        (
            Request::Configure {
                boot_id: BootId(7),
                os: Os::Linux,
            },
            Error::UnexpectedOs,
        ),
        (
            Request::Configure {
                boot_id: BootId(8),
                os: Os::Windows,
            },
            Error::TargetMissing,
        ),
    ] {
        let mut p = FakePlatform::missing();
        assert_eq!(execute(request, Os::Linux, &mut p), Err(expected));
        assert!(!p.events.iter().any(Event::is_mutation));
    }
}

fn switch() -> Request {
    Request::Switch { os: Os::Windows }
}

fn success_events() -> Vec<Event> {
    vec![
        Event::ReadRecord,
        Event::CheckEnvironment,
        Event::ReadOptions,
        Event::ReadNext,
        Event::ReadNext,
        Event::WriteNext(BootId(7)),
        Event::ReadNext,
        Event::Reboot,
    ]
}

fn assert_failure(error: Error, cause: Error, stages: &[Stage], assessment: ResidualAssessment) {
    assert_eq!(
        error.residual_possible(),
        stages.contains(&Stage::ResidualPossible)
    );
    let Error::FlowFailure {
        cause: actual,
        stages: actual_stages,
        residual_assessment,
        ..
    } = error
    else {
        panic!("failure must retain completed stages: {error:?}")
    };
    assert_eq!(*actual, cause);
    assert_eq!(actual_stages, stages);
    assert_eq!(residual_assessment, assessment);
}

#[test]
fn unchanged_switch_validates_writes_reads_back_then_requests_reboot() {
    let mut p = FakePlatform::ready();
    let report = execute(switch(), Os::Linux, &mut p).unwrap();
    assert_eq!(p.events, success_events());
    assert_eq!(p.next, Some(BootId(7)));
    assert_eq!(
        report.stages,
        [
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootAccepted
        ]
    );
}

#[test]
fn same_boot_next_skips_write_but_requires_independent_readback() {
    let mut p = FakePlatform::ready();
    p.next = Some(BootId(7));
    let report = execute(switch(), Os::Linux, &mut p).unwrap();
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions,
            Event::ReadNext,
            Event::ReadNext,
            Event::Reboot
        ]
    );
    assert_eq!(
        report.stages,
        [
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootAccepted
        ]
    );
}

#[test]
fn boot_next_conflict_stops_at_initial_and_prewrite_checks() {
    for reads in [
        vec![Ok(Some(BootId(9)))],
        vec![Ok(None), Ok(Some(BootId(9)))],
    ] {
        let read_count = reads.len();
        let mut p = FakePlatform::ready();
        p.next_reads = reads.into();
        assert_failure(
            execute(switch(), Os::Linux, &mut p).unwrap_err(),
            Error::BootNextConflict,
            &[Stage::TargetValidated],
            ResidualAssessment::NotChecked,
        );
        assert_eq!(p.events, success_events()[..3 + read_count]);
        assert!(!p.events.iter().any(Event::is_mutation));
    }
}

#[test]
fn target_appearing_at_prewrite_check_is_not_overwritten() {
    let mut p = FakePlatform::ready();
    p.next_reads = [Ok(None), Ok(Some(BootId(7))), Ok(Some(BootId(7)))].into();
    execute(switch(), Os::Linux, &mut p).unwrap();
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions,
            Event::ReadNext,
            Event::ReadNext,
            Event::ReadNext,
            Event::Reboot
        ]
    );
}

#[test]
fn readback_mismatch_never_reboots_or_cleans_up() {
    for initial in [None, Some(BootId(7))] {
        for readback in [None, Some(BootId(8))] {
            let mut p = FakePlatform::ready();
            p.next = initial;
            p.next_reads = if initial.is_none() {
                vec![Ok(None), Ok(None), Ok(readback)]
            } else {
                vec![Ok(initial), Ok(readback)]
            }
            .into();
            assert_failure(
                execute(switch(), Os::Linux, &mut p).unwrap_err(),
                Error::ReadbackFailed,
                &[Stage::TargetValidated, Stage::ResidualPossible],
                ResidualAssessment::NotChecked,
            );
            assert!(!p.events.contains(&Event::Reboot));
            assert_eq!(
                p.events
                    .iter()
                    .filter(|e| matches!(e, Event::WriteNext(_)))
                    .count(),
                usize::from(initial.is_none())
            );
        }
    }
}

#[test]
fn switch_requires_registered_opposite_os() {
    let mut p = FakePlatform::missing();
    assert_eq!(
        execute(switch(), Os::Linux, &mut p),
        Err(Error::NotConfigured)
    );
    assert!(!p.events.iter().any(Event::is_mutation));
    let mut p = FakePlatform::ready();
    assert_eq!(
        execute(Request::Switch { os: Os::Linux }, Os::Linux, &mut p),
        Err(Error::UnexpectedOs)
    );
    if let Ok(RecordState::Ready(record)) = &mut p.record {
        record.os = Os::Linux;
    }
    assert_eq!(
        execute(switch(), Os::Linux, &mut p),
        Err(Error::UnexpectedOs)
    );
    assert!(!p.events.iter().any(Event::is_mutation));
    // Host rules work symmetrically; this is a shared enum test, not Windows adapter evidence.
    execute(Request::Switch { os: Os::Linux }, Os::Windows, &mut p).unwrap();
}

#[test]
fn missing_original_id_stops() {
    let mut p = FakePlatform::ready();
    p.options[0].0 = BootId(8);
    assert_eq!(
        execute(switch(), Os::Linux, &mut p),
        Err(Error::TargetMissing)
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

#[test]
fn identity_mismatch_has_no_write_reboot_save() {
    // Every mutation changes a single valid identity field, so format rejection cannot mask mismatch.
    for field in 0..8 {
        let mut p = FakePlatform::ready();
        let Ok(RecordState::Ready(record)) = &mut p.record else {
            unreachable!()
        };
        let identity = &mut record.identity;
        match field {
            0..=3 => {
                let CanonicalDevicePathNode::HardDrive(hd) = &mut identity.nodes[0] else {
                    unreachable!()
                };
                match field {
                    0 => hd.partition_number += 1,
                    1 => hd.partition_start_lba += 1,
                    2 => hd.partition_size_lba += 1,
                    _ => hd.partition_signature_uefi_bytes[0] ^= 1,
                }
            }
            4..=5 => {
                let CanonicalDevicePathNode::FilePath(path) = &mut identity.nodes[1] else {
                    unreachable!()
                };
                path.path_utf16[1] = if field == 4 { b'e' as u16 } else { b'Z' as u16 };
            }
            6 => identity.optional_data.byte_length += 1,
            _ => identity.optional_data.digest[0] ^= 1,
        }
        encode_record(record).expect("single-field mutation remains a valid record");
        assert_eq!(
            execute(switch(), Os::Linux, &mut p),
            Err(Error::IdentityMismatch),
            "field {field}"
        );
        assert!(!p.events.iter().any(Event::is_mutation));
    }
}

#[test]
fn id_reuse_mismatch_stops() {
    let mut p = FakePlatform::ready();
    p.options[0].1.optional_data[0] ^= 1;
    p.options.push((BootId(8), support::option()));
    assert_eq!(
        execute(switch(), Os::Linux, &mut p),
        Err(Error::IdentityMismatch)
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

#[test]
fn explicit_reconfirm_saves_new_baseline() {
    let mut p = FakePlatform::ready();
    p.options[0].1.optional_data.push(0);
    assert_eq!(
        execute(switch(), Os::Linux, &mut p),
        Err(Error::IdentityMismatch)
    );
    execute(requests()[1], Os::Linux, &mut p).unwrap();
    let Ok(RecordState::Ready(record)) = &p.record else {
        unreachable!()
    };
    assert_eq!(record.identity.optional_data.byte_length, 5);
    assert_eq!(record.identity, canonicalize(&p.options[0].1).unwrap());
    p.events.clear();
    execute(switch(), Os::Linux, &mut p).unwrap();
    assert!(!p.events.contains(&Event::SaveRecord));
    p.options[0].1.optional_data.push(0);
    p.events.clear();
    assert_eq!(
        execute(switch(), Os::Linux, &mut p),
        Err(Error::IdentityMismatch)
    );
    assert!(!p.events.iter().any(Event::is_mutation));
}

#[test]
fn configure_failure_preserves_store_durability_without_firmware_residual() {
    let cause = Error::StoreDurabilityUnknown { raw_code: 5 };
    let mut p = FakePlatform::missing();
    p.failure = Some((3, cause.clone()));
    assert_failure(
        execute(requests()[1], Os::Linux, &mut p).unwrap_err(),
        cause,
        &[Stage::TargetValidated],
        ResidualAssessment::NotChecked,
    );
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions,
            Event::SaveRecord
        ]
    );
}

#[test]
fn every_fallible_switch_call_preserves_cause_and_stops() {
    for index in 0..7 {
        let cause = Error::PlatformIo {
            operation: if index == 5 {
                PlatformOperation::Write
            } else {
                PlatformOperation::Read
            },
            raw_code: 100 + index as i32,
        };
        let mut p = FakePlatform::ready();
        p.failure = Some((index, cause.clone()));
        let error = execute(switch(), Os::Linux, &mut p).unwrap_err();
        if index < 3 {
            assert_eq!(error, cause);
        } else {
            let stages = if index >= 5 {
                vec![Stage::TargetValidated, Stage::ResidualPossible]
            } else {
                vec![Stage::TargetValidated]
            };
            assert_failure(error, cause, &stages, ResidualAssessment::NotChecked);
        }
        assert_eq!(p.events, success_events()[..=index]);
    }
}

#[test]
fn failed_write_can_leave_state_and_is_never_retried() {
    for mutates in [false, true] {
        let mut p = FakePlatform::ready();
        p.write_error_mutates = mutates;
        let cause = Error::PlatformIo {
            operation: PlatformOperation::Write,
            raw_code: 4,
        };
        p.failure = Some((5, cause.clone()));
        assert_failure(
            execute(switch(), Os::Linux, &mut p).unwrap_err(),
            cause,
            &[Stage::TargetValidated, Stage::ResidualPossible],
            ResidualAssessment::NotChecked,
        );
        assert_eq!(p.next, if mutates { Some(BootId(7)) } else { None });
        assert_eq!(p.events, success_events()[..6]);
    }
}

#[test]
fn reboot_rejected_assesses_without_restoration() {
    for (observed, residual) in [
        (Some(BootId(7)), true),
        (Some(BootId(8)), true),
        (None, false),
    ] {
        let mut p = FakePlatform::ready();
        p.reboot_outcome = RebootOutcome::Rejected;
        p.next_reads = [Ok(None), Ok(None), Ok(Some(BootId(7))), Ok(observed)].into();
        let mut stages = vec![
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootRejected,
        ];
        if observed == Some(BootId(7)) {
            stages.extend([
                Stage::RollbackAttempted,
                Stage::RollbackUnsafe,
                Stage::ResidualPossible,
            ]);
        } else if residual {
            stages.extend([Stage::RollbackUnsafe, Stage::ResidualPossible]);
        }
        assert_failure(
            execute(switch(), Os::Linux, &mut p).unwrap_err(),
            Error::RebootRejected,
            &stages,
            ResidualAssessment::Observed(observed),
        );
        let mut expected = success_events();
        expected.push(Event::ReadNext);
        if observed == Some(BootId(7)) {
            expected.push(Event::RollbackNext {
                original: None,
                written: BootId(7),
            });
        }
        assert_eq!(p.events, expected);
    }
}

#[test]
fn reboot_rejected_assessment_failure_retains_raw_error() {
    let mut p = FakePlatform::ready();
    p.reboot_outcome = RebootOutcome::Rejected;
    let read_error = Error::PlatformIo {
        operation: PlatformOperation::Read,
        raw_code: 19,
    };
    p.failure = Some((8, read_error.clone()));
    assert_failure(
        execute(switch(), Os::Linux, &mut p).unwrap_err(),
        Error::RebootRejected,
        &[
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootRejected,
            Stage::RollbackUnsafe,
            Stage::ResidualPossible,
        ],
        ResidualAssessment::ReadFailed(Box::new(read_error)),
    );
    let mut expected = success_events();
    expected.push(Event::ReadNext);
    assert_eq!(p.events, expected);
}

#[test]
fn reboot_unknown_reports_uncertainty_without_rollback() {
    let mut p = FakePlatform::ready();
    p.reboot_outcome = RebootOutcome::Unknown;
    let report = execute(switch(), Os::Linux, &mut p).unwrap();
    assert_eq!(
        report.stages,
        [
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootUnknown,
            Stage::ResidualPossible
        ]
    );
    assert_eq!(p.events, success_events());
}

// A typed Ready value must not let a broken adapter bypass record invariants or overwrite it.
#[test]
fn corrupt_typed_ready_record_is_revalidated_before_all_operations() {
    for request in requests() {
        let mut p = FakePlatform::ready();
        let Ok(RecordState::Ready(record)) = &mut p.record else {
            unreachable!()
        };
        record.identity.file_path_list_length += 1;
        assert_eq!(
            execute(request, Os::Linux, &mut p),
            Err(Error::CorruptRecord)
        );
        assert_eq!(p.events, [Event::ReadRecord]);
    }
}

fn encoded_ready() -> serde_json::Value {
    let p = FakePlatform::ready();
    let Ok(RecordState::Ready(record)) = p.record else {
        unreachable!()
    };
    serde_json::from_slice(&encode_record(&record).unwrap()).unwrap()
}

#[test]
fn unknown_algorithm_stops() {
    let mut value = encoded_ready();
    value["target"]["identity"]["optional_data"]["algorithm"] = "FutureHash".into();
    for request in requests() {
        let mut p = FakePlatform::missing();
        p.record = decode_record(&serde_json::to_vec(&value).unwrap()).map(RecordState::Ready);
        assert_eq!(
            execute(request, Os::Linux, &mut p),
            Err(Error::UnsupportedIdentityComponent)
        );
        assert_eq!(p.events, [Event::ReadRecord]);
    }
}

#[test]
fn bad_digest_or_derived_length_corrupt() {
    let good = encoded_ready();
    let mut digest = good.clone();
    digest["target"]["identity"]["optional_data"]["digest"] = "00".into();
    let mut length = good;
    length["target"]["identity"]["file_path_list_length"] = 93.into();
    for value in [digest, length] {
        for request in requests() {
            let mut p = FakePlatform::missing();
            p.record = decode_record(&serde_json::to_vec(&value).unwrap()).map(RecordState::Ready);
            assert_eq!(
                execute(request, Os::Linux, &mut p),
                Err(Error::CorruptRecord)
            );
            assert_eq!(p.events, [Event::ReadRecord]);
        }
    }
}

#[test]
fn unsupported_component_configure_preserves_record() {
    for pointer in [
        "/target/identity/version",
        "/target/identity/optional_data/version",
    ] {
        let mut value = encoded_ready();
        *value.pointer_mut(pointer).unwrap() = 999.into();
        let mut p = FakePlatform::missing();
        p.record = decode_record(&serde_json::to_vec(&value).unwrap()).map(RecordState::Ready);
        let before = p.record.clone();
        assert_eq!(
            execute(requests()[1], Os::Linux, &mut p),
            Err(Error::UnsupportedIdentityComponent)
        );
        assert_eq!(p.record, before);
        assert_eq!(p.events, [Event::ReadRecord]);
    }
}

#[test]
fn gui_digest_not_trusted() {
    let mut p = FakePlatform::ready();
    // The request carries only id and explicit OS. Even the old stored digest is not input
    // to configuration; structural fields and the whole new opaque body share one option.
    p.options[0].1.optional_data = b"abc".to_vec();
    execute(requests()[1], Os::Linux, &mut p).unwrap();
    let Ok(RecordState::Ready(record)) = p.record else {
        unreachable!()
    };
    assert_eq!(record.identity.file_path_list_length, 94);
    assert_eq!(record.identity.optional_data.byte_length, 3);
    assert_eq!(
        record.identity.optional_data.digest,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions,
            Event::SaveRecord
        ]
    );
}

#[test]
fn malformed_path_even_matching_digest_rejected() {
    for request in [requests()[1], switch()] {
        let mut p = FakePlatform::ready();
        p.options[0].1.file_paths[0].instances[0].nodes[1].node_type = 1;
        assert_eq!(
            execute(request, Os::Linux, &mut p),
            Err(Error::UnsupportedFormat)
        );
        assert!(!p.events.iter().any(Event::is_mutation));
    }
}

#[test]
fn load_attributes_and_description_are_revalidated_each_time() {
    for field in 0..3 {
        let mut p = FakePlatform::ready();
        execute(Request::Inspect, Os::Linux, &mut p).unwrap();
        match field {
            0 => p.options[0].1.attributes = 0,
            1 => p.options[0].1.attributes = 3,
            _ => p.options[0].1.description_utf16 = vec![0xd800],
        }
        assert_eq!(
            execute(Request::Inspect, Os::Linux, &mut p),
            Err(Error::UnsupportedFormat)
        );
        for request in [requests()[1], switch()] {
            assert_eq!(
                execute(request, Os::Linux, &mut p),
                Err(Error::UnsupportedFormat)
            );
        }
        assert!(!p.events.iter().any(Event::is_mutation));
    }
}

#[test]
fn valid_description_and_hidden_changes_allow_switch() {
    let mut p = FakePlatform::ready();
    p.options[0].1.description_utf16 = "renamed".encode_utf16().collect();
    p.options[0].1.attributes = 9;
    execute(switch(), Os::Linux, &mut p).unwrap();
    assert_eq!(p.events, success_events());
}

#[test]
fn every_inspect_and_configure_call_failure_stops_and_retains_raw_code() {
    let events = [
        Event::ReadRecord,
        Event::CheckEnvironment,
        Event::ReadOptions,
        Event::SaveRecord,
    ];
    for (request, count) in [(Request::Inspect, 3), (requests()[1], 4)] {
        for index in 0..count {
            let mut p = FakePlatform::missing();
            let cause = Error::PlatformIo {
                operation: if index == 3 {
                    PlatformOperation::Replace
                } else {
                    PlatformOperation::Read
                },
                raw_code: 13,
            };
            p.failure = Some((index, cause.clone()));
            let error = execute(request, Os::Linux, &mut p).unwrap_err();
            if index < 3 {
                assert_eq!(error, cause);
            } else {
                let stages = if matches!(request, Request::Configure { .. }) {
                    &[Stage::TargetValidated][..]
                } else {
                    &[Stage::TargetValidated, Stage::ResidualPossible][..]
                };
                assert_failure(error, cause, stages, ResidualAssessment::NotChecked);
            }
            assert_eq!(p.events, events[..=index]);
        }
    }
}

#[test]
fn adapter_variable_attribute_and_incomplete_enumeration_failures_propagate() {
    for cause in [
        Error::UnsupportedFormat,
        Error::ResourceLimit,
        Error::MalformedLoadOption,
    ] {
        for request in requests() {
            let mut p = FakePlatform::ready();
            p.failure = Some((2, cause.clone()));
            assert_eq!(execute(request, Os::Linux, &mut p), Err(cause.clone()));
            assert_eq!(
                p.events,
                [
                    Event::ReadRecord,
                    Event::CheckEnvironment,
                    Event::ReadOptions
                ]
            );
        }
    }
}

#[test]
fn same_target_readback_error_preserves_residual_without_write() {
    let mut p = FakePlatform::ready();
    p.next = Some(BootId(7));
    let cause = Error::PlatformIo {
        operation: PlatformOperation::Read,
        raw_code: 5,
    };
    p.failure = Some((4, cause.clone()));
    assert_failure(
        execute(switch(), Os::Linux, &mut p).unwrap_err(),
        cause,
        &[Stage::TargetValidated, Stage::ResidualPossible],
        ResidualAssessment::NotChecked,
    );
    assert_eq!(
        p.events,
        [
            Event::ReadRecord,
            Event::CheckEnvironment,
            Event::ReadOptions,
            Event::ReadNext,
            Event::ReadNext
        ]
    );
}

#[test]
fn opaque_tail_append_truncate_and_empty_changes_stop_switch() {
    for optional in [vec![0, 255, 128, 127, 0], vec![0, 255, 128], vec![]] {
        let mut p = FakePlatform::ready();
        p.options[0].1.optional_data = optional;
        assert_eq!(
            execute(switch(), Os::Linux, &mut p),
            Err(Error::IdentityMismatch)
        );
        assert!(!p.events.iter().any(Event::is_mutation));
    }
}

#[test]
fn duplicate_boot_ids_are_rejected_without_choosing_first() {
    for same_identity in [false, true] {
        for request in requests() {
            let mut p = FakePlatform::ready();
            let mut duplicate = p.options[0].1.clone();
            if !same_identity {
                duplicate.optional_data.push(0);
            }
            p.options.push((BootId(7), duplicate));
            assert_eq!(
                execute(request, Os::Linux, &mut p),
                Err(Error::UnsupportedFormat)
            );
            assert_eq!(
                p.events,
                [
                    Event::ReadRecord,
                    Event::CheckEnvironment,
                    Event::ReadOptions
                ]
            );
        }
    }
}
// Catches silently dropping platform discovery diagnostics at the core boundary.
#[test]
fn inventory_diagnostics_survive_reports_and_structured_failures() {
    use boothop_core::EnumerationDiagnostic::DuplicateBootOrder;
    for request in [
        Request::Inspect,
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows,
        },
        Request::Switch { os: Os::Windows },
    ] {
        let mut p = support::FakePlatform::ready();
        p.diagnostics = vec![DuplicateBootOrder(BootId(7))];
        let report = execute(request, Os::Linux, &mut p).unwrap();
        assert_eq!(report.diagnostics, [DuplicateBootOrder(BootId(7))]);
    }
    let mut p = support::FakePlatform::ready();
    p.diagnostics = vec![DuplicateBootOrder(BootId(7))];
    p.next = Some(BootId(8));
    let Error::FlowFailure { diagnostics, .. } =
        execute(Request::Switch { os: Os::Windows }, Os::Linux, &mut p).unwrap_err()
    else {
        panic!("expected structured failure")
    };
    assert_eq!(diagnostics, [DuplicateBootOrder(BootId(7))]);
}
