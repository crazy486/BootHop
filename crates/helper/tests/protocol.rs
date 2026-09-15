use boothop_core::{BootId, Os, Request};
use boothop_core::{
    Candidate, Classification, EnumerationDiagnostic, Error, PlatformOperation, RecordDiagnostic,
    Report, ResidualAssessment, RollbackAssessment, Stage,
};
use boothop_helper::protocol::*;
use boothop_helper::protocol::{decode_request, encode_request};

#[test]
fn v2_id_is_exact_nonzero_lowercase_and_response_echo_is_checked() {
    let id = RequestId::parse("0123456789abcdef0123456789abcde1").unwrap();
    let request = encode_request_with_id(&id, Request::Inspect).unwrap();
    assert_eq!(decode_request_envelope(&request).unwrap().request_id, id);
    let response = encode_response_with_id(&id, Err(Error::Busy)).unwrap();
    assert_eq!(decode_response_for(&response, &id), Ok(Err(Error::Busy)));
    let other = RequestId::parse("0123456789abcdef0123456789abcde2").unwrap();
    assert_eq!(
        decode_response_for(&response, &other),
        Err(ProtocolError::Invalid)
    );
    for value in [
        "",
        "0",
        "00000000000000000000000000000000",
        "0123456789ABCDEF0123456789abcdef",
        "0123456789abcdef0123456789abcde",
    ] {
        assert!(
            RequestId::parse(value).is_err(),
            "accepted invalid request_id {value:?}"
        );
    }
}

#[test]
fn v2_rejects_missing_id_and_credential_or_arbitrary_transport_fields() {
    let raw = |json: &str| {
        let mut frame = (json.len() as u32).to_le_bytes().to_vec();
        frame.extend(json.as_bytes());
        frame
    };
    assert!(decode_request(&raw(r#"{"protocol_version":2,"request":"Inspect"}"#)).is_err());
    assert!(decode_request(&raw(r#"{"protocol_version":2,"request_id":"0123456789abcdef0123456789abcde1","request":"Inspect","credential":"x"}"#)).is_err());
    assert!(decode_request(&raw(r#"{"protocol_version":2,"request_id":"0123456789abcdef0123456789abcde1","request":"Inspect","path":"C:\\x"}"#)).is_err());
}

#[test]
fn duplicate_keys_are_rejected_recursively_without_value_normalization() {
    let raw = |json: &str| {
        let mut frame = (json.len() as u32).to_le_bytes().to_vec();
        frame.extend(json.as_bytes());
        frame
    };
    let id = "0123456789abcdef0123456789abcde1";
    let cases = [
        (
            format!(
                r#"{{"protocol_version":2,"request_id":"{id}","request":"Inspect","request_id":"{id}"}}"#
            ),
            true,
        ),
        (
            format!(
                r#"{{"protocol_version":2,"request_id":"{id}","request":{{"Switch":{{"os":"Windows","os":"Windows"}}}}}}"#
            ),
            true,
        ),
        (
            format!(
                r#"{{"protocol_version":2,"request_id":"{id}","request":"Inspect","request\u005fid":"{id}"}}"#
            ),
            true,
        ),
        (
            format!(
                r#"{{"protocol_version":2,"request_id":"{id}","result":{{"Err":{{"FlowFailure":{{"cause":"Busy","stages":[],"residual_assessment":"NotChecked","rollback_assessment":"NotNeeded","diagnostics":[],"diagnostics":[]}}}}}}}}"#
            ),
            false,
        ),
    ];
    for (json, request) in cases {
        let rejected = if request {
            decode_request(&raw(&json)).is_err()
        } else {
            decode_response(&raw(&json)).is_err()
        };
        assert!(rejected, "duplicate accepted: {json}");
    }
}

#[test]
fn task6_protocol_is_v2_and_requires_request_correlation() {
    assert_eq!(boothop_helper::protocol::PROTOCOL_VERSION, 2);
    let frame = frame(
        r#"{"protocol_version":2,"request_id":"00000000000000000000000000000001","request":"Inspect"}"#,
    );
    assert!(decode_request(&frame).is_ok());
}

fn frame(json: &str) -> Vec<u8> {
    // Insert the fixture ID textually so malformed duplicate keys remain in
    // the original bytes (a Value round-trip would erase the defect).
    let mut body = json.to_owned();
    if !json.contains("\"request_id\"") {
        let marker = if json.contains("\"request\"") {
            "\"request\""
        } else if json.contains("\"result\"") {
            "\"result\""
        } else {
            ""
        };
        if !marker.is_empty() {
            let position = json.find(marker).unwrap();
            body.insert_str(
                position,
                "\"request_id\":\"00000000000000000000000000000001\",",
            );
        }
    }
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend(body.as_bytes());
    frame
}

#[test]
fn request_and_hello_require_canonical_object_shapes() {
    let requests = [
        r#"[1,"Inspect"]"#,
        r#"{"protocol_version":2,"request":{"Configure":[7,"Windows"]}}"#,
        r#"{"protocol_version":2,"request":{"Switch":["Windows"]}}"#,
        r#"{"protocol_version":2,"request":{"Inspect":null}}"#,
        r#"{"protocol_version":2,"request":{"Switch":{"os":{"Windows":null}}}}"#,
        r#"{"protocol_version":2,"request":{"Switch":{"os":{"Linux":null}}}}"#,
        r#"{"protocol_version":2,"request":["Inspect"]}"#,
    ];
    let accepted: Vec<_> = requests
        .into_iter()
        .filter(|json| decode_request(&frame(json)).is_ok())
        .collect();
    assert!(
        accepted.is_empty(),
        "accepted noncanonical requests: {accepted:?}"
    );
    assert_eq!(
        decode_hello(&frame("[1,true]")),
        Err(ProtocolError::Invalid)
    );
}

/// The expected sequence field order is deliberately specified by literals,
/// independently of serde's serializer. Every reachable struct payload appears.
#[test]
fn all_response_struct_payloads_require_maps_including_recursive_errors() {
    use serde_json::json;
    let empty_report = json!({"candidates":[],"record":"Missing","stages":[],"diagnostics":[]});
    let flow = json!({"FlowFailure":{"cause":"Busy","stages":[],"residual_assessment":"NotChecked","rollback_assessment":"NotNeeded","diagnostics":[]}});
    let cases = [
        (
            "response",
            json!({"protocol_version":2,"result":{"Err":"Busy"}}),
            "",
            json!([1,{"Err":"Busy"}]),
        ),
        (
            "report",
            json!({"protocol_version":2,"result":{"Ok":empty_report}}),
            "/result/Ok",
            json!([[], "Missing", [], []]),
        ),
        (
            "candidate",
            json!({"protocol_version":2,"result":{"Ok":{"candidates":[{"boot_id":7,"description_utf16":[65],"classification":"NeedsConfirmation","ambiguous":false}],"record":"Missing","stages":[],"diagnostics":[]}}}),
            "/result/Ok/candidates/0",
            json!([7, [65], "NeedsConfirmation", false]),
        ),
        (
            "record ready",
            json!({"protocol_version":2,"result":{"Ok":{"candidates":[],"record":{"Ready":{"boot_id":7,"os":"Windows"}},"stages":[],"diagnostics":[]}}}),
            "/result/Ok/record/Ready",
            json!([7, "Windows"]),
        ),
        (
            "record version error",
            json!({"protocol_version":2,"result":{"Err":{"UnsupportedRecordVersion":{"found":999}}}}),
            "/result/Err/UnsupportedRecordVersion",
            json!([999]),
        ),
        (
            "platform error",
            json!({"protocol_version":2,"result":{"Err":{"PlatformIo":{"operation":"Read","raw_code":5}}}}),
            "/result/Err/PlatformIo",
            json!(["read", 5]),
        ),
        (
            "durability error",
            json!({"protocol_version":2,"result":{"Err":{"StoreDurabilityUnknown":{"raw_code":5}}}}),
            "/result/Err/StoreDurabilityUnknown",
            json!([5]),
        ),
        (
            "flow error",
            json!({"protocol_version":2,"result":{"Err":flow}}),
            "/result/Err/FlowFailure",
            json!(["Busy", [], "NotChecked", "NotNeeded", []]),
        ),
        (
            "recursive cause",
            json!({"protocol_version":2,"result":{"Err":{"FlowFailure":{"cause":flow,"stages":[],"residual_assessment":"NotChecked","rollback_assessment":"NotNeeded","diagnostics":[]}}}}),
            "/result/Err/FlowFailure/cause/FlowFailure",
            json!(["Busy", [], "NotChecked", "NotNeeded", []]),
        ),
        (
            "recursive residual",
            json!({"protocol_version":2,"result":{"Err":{"FlowFailure":{"cause":"Busy","stages":[],"residual_assessment":{"ReadFailed":{"StoreDurabilityUnknown":{"raw_code":5}}},"rollback_assessment":"NotNeeded","diagnostics":[]}}}}),
            "/result/Err/FlowFailure/residual_assessment/ReadFailed/StoreDurabilityUnknown",
            json!([5]),
        ),
    ];
    let mut accepted = vec![];
    for (name, mut original, pointer, malformed) in cases {
        assert!(
            decode_response(&frame(&original.to_string())).is_ok(),
            "invalid canonical fixture: {name}"
        );
        // Raw duplicate insertion must still be rejected before Value parsing
        // could normalize it. Exercise every object shape in the same matrix.
        let object = original.pointer(pointer).unwrap();
        let (key, value) = object.as_object().unwrap().iter().next().unwrap();
        let object_json = object.to_string();
        let duplicated = format!(
            "{{{}:{value},{}",
            serde_json::to_string(key).unwrap(),
            &object_json[1..]
        );
        let duplicate_json = original.to_string().replacen(&object_json, &duplicated, 1);
        assert!(
            decode_response(&frame(&duplicate_json)).is_err(),
            "duplicate accepted: {name}"
        );
        *original.pointer_mut(pointer).unwrap() = malformed;
        if decode_response(&frame(&original.to_string())).is_ok() {
            accepted.push(name);
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted array-for-object: {accepted:?}"
    );
}

#[test]
fn canonical_shape_allows_field_order_whitespace_and_equivalent_escapes() {
    assert_eq!(
        decode_request(&frame(
            r#"{ "request" : { "Switch" : { "os" : "\u0057indows" } }, "protocol_version":2 }"#
        )),
        Ok(Request::Switch { os: Os::Windows })
    );
    assert_eq!(
        decode_hello(&frame(r#"{ "hello": true, "protocol_version":2 }"#)),
        Ok(())
    );
    assert_eq!(
        decode_response(&frame(
            r#"{ "result" : { "Err" : { "PlatformIo" : { "raw_code": 5, "operation": "Read" } } }, "protocol_version":2 }"#
        )),
        Ok(Err(Error::PlatformIo {
            operation: PlatformOperation::Read,
            raw_code: 5
        }))
    );
}

#[test]
fn all_unit_enum_families_reject_object_and_array_alternatives() {
    use serde_json::json;
    let mut cases = vec![];
    for variant in [
        "MalformedLoadOption",
        "MalformedDevicePath",
        "ResourceLimit",
        "UnsupportedFormat",
        "UnsupportedIdentityComponent",
        "CorruptRecord",
        "IdentityMismatch",
        "UnexpectedOs",
        "TargetMissing",
        "NotConfigured",
        "BootNextConflict",
        "Busy",
        "ReadbackFailed",
        "RebootRejected",
        "NotUefi",
        "PrivilegeUnavailable",
    ] {
        cases.push((
            json!({"protocol_version":2,"result":{"Err":variant}}),
            "/result/Err",
        ));
    }
    for variant in [
        "TargetValidated",
        "BootNextVerified",
        "RebootAccepted",
        "RebootRejected",
        "RebootUnknown",
        "RollbackAttempted",
        "RollbackRestored",
        "RollbackUnsafe",
        "RollbackFailed",
        "ResidualPossible",
    ] {
        cases.push((json!({"protocol_version":2,"result":{"Ok":{"candidates":[],"record":"Missing","stages":[variant],"diagnostics":[]}}}), "/result/Ok/stages/0"));
    }
    for variant in ["NeedsConfirmation", "Unsupported"] {
        cases.push((json!({"protocol_version":2,"result":{"Ok":{"candidates":[{"boot_id":7,"description_utf16":[],"classification":variant,"ambiguous":false}],"record":"Missing","stages":[],"diagnostics":[]}}}), "/result/Ok/candidates/0/classification"));
    }
    cases.push((json!({"protocol_version":2,"result":{"Ok":{"candidates":[],"record":"Missing","stages":[],"diagnostics":[]}}}), "/result/Ok/record"));
    cases.push((json!({"protocol_version":2,"result":{"Err":{"FlowFailure":{"cause":"Busy","stages":[],"residual_assessment":"NotChecked","rollback_assessment":"NotNeeded","diagnostics":[]}}}}), "/result/Err/FlowFailure/residual_assessment"));
    for variant in ["Windows", "Linux"] {
        cases.push((json!({"protocol_version":2,"result":{"Ok":{"candidates":[],"record":{"Ready":{"boot_id":7,"os":variant}},"stages":[],"diagnostics":[]}}}), "/result/Ok/record/Ready/os"));
    }
    let mut accepted = vec![];
    for (original, pointer) in cases {
        assert!(decode_response(&frame(&original.to_string())).is_ok());
        let variant = original.pointer(pointer).unwrap().as_str().unwrap();
        for malformed in [json!({variant:null}), json!([variant])] {
            let mut mutated = original.clone();
            *mutated.pointer_mut(pointer).unwrap() = malformed;
            if decode_response(&frame(&mutated.to_string())).is_ok() {
                accepted.push(variant.to_owned());
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted noncanonical unit enums: {accepted:?}"
    );
}
fn report() -> Report {
    Report {
        candidates: vec![
            Candidate {
                boot_id: BootId(0),
                description_utf16: vec![0, 0xd800, 65535],
                classification: Classification::NeedsConfirmation,
                ambiguous: true,
            },
            Candidate {
                boot_id: BootId(65535),
                description_utf16: vec![],
                classification: Classification::Unsupported,
                ambiguous: false,
            },
        ],
        record: RecordDiagnostic::Ready {
            boot_id: BootId(65535),
            os: Os::Windows,
        },
        stages: vec![
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootAccepted,
            Stage::RebootRejected,
            Stage::RebootUnknown,
            Stage::RollbackAttempted,
            Stage::RollbackRestored,
            Stage::RollbackUnsafe,
            Stage::RollbackFailed,
            Stage::ResidualPossible,
        ],
        diagnostics: vec![EnumerationDiagnostic::DuplicateBootOrder(BootId(42))],
    }
}

#[test]
fn hostile_request_fields_types_and_duplicate_keys_rejected() {
    for extra in [
        "host",
        "path",
        "command",
        "record",
        "identity",
        "digest",
        "optional_data",
        "BootOrder",
        "BootNext",
        "cache",
    ] {
        for request in [
            format!(r#"{{"Switch":{{"os":"Windows","{extra}":7}}}}"#),
            format!(r#"{{"Configure":{{"os":"Windows","boot_id":7,"{extra}":7}}}}"#),
        ] {
            assert!(
                decode_request(&frame(&format!(
                    r#"{{"protocol_version":2,"request":{request}}}"#
                )))
                .is_err(),
                "{extra}"
            );
        }
        assert!(
            decode_request(&frame(&format!(
                r#"{{"protocol_version":2,"request":"Inspect","{extra}":7}}"#
            )))
            .is_err()
        );
    }
    for json in [
        r#"{"protocol_version":2,"protocol_version":2,"request":"Inspect"}"#,
        r#"{"protocol_version":2,"request":"Inspect","request":"Inspect"}"#,
        r#"{"protocol_version":2,"request":{"Switch":{"os":"Windows","os":"Linux"}}}"#,
        r#"{"protocol_version":2,"request":{"Configure":{"os":"Windows","boot_id":7,"boot_id":8}}}"#,
        r#"{"protocol_version":2,"request":{"Switch":{"os":"Other"}}}"#,
        r#"{"protocol_version":"1","request":"Inspect"}"#,
        r#"{"protocol_version":2,"request":{"Configure":{"os":"Windows","boot_id":65536}}}"#,
        r#"{"protocol_version":2,"request":{"Configure":{"os":"Windows","boot_id":-1}}}"#,
        r#"{"protocol_version":2,"request":"Delete"}"#,
        r#"{"protocol_version":2,"request":null}"#,
    ] {
        assert!(decode_request(&frame(json)).is_err(), "{json}");
    }
}
#[test]
fn version_truncation_trailing_and_frame_limit_fail_closed() {
    assert_eq!(
        decode_request(&frame(r#"{"protocol_version":1,"request":"Inspect"}"#)),
        Err(ProtocolError::Version)
    );
    let bytes = encode_request(Request::Inspect).unwrap();
    for n in 0..bytes.len() {
        assert!(decode_request(&bytes[..n]).is_err());
    }
    assert!(decode_request(&[bytes.clone(), vec![0]].concat()).is_err());
    assert!(decode_request(&frame(r#"{"protocol_version":2,"request":"Inspect"} {}"#)).is_err());
    assert_eq!(
        decode_request(&65533_u32.to_le_bytes()),
        Err(ProtocolError::ResourceLimit)
    );
    assert_eq!(
        decode_request(&vec![0; 65537]),
        Err(ProtocolError::ResourceLimit)
    );
}
#[test]
fn hello_is_strict_and_versioned() {
    assert_eq!(decode_hello(&encode_hello()), Ok(()));
    for json in [
        r#"{"protocol_version":2,"hello":false}"#,
        r#"{"protocol_version":2,"hello":true,"hello":true}"#,
        r#"{"protocol_version":2,"hello":true,"path":"/tmp"}"#,
    ] {
        assert!(decode_hello(&frame(json)).is_err());
    }
}
#[test]
fn store_durability_unknown_error_wire_roundtrip() {
    for raw_code in [i32::MIN, 5, i32::MAX] {
        let result = Err(Error::StoreDurabilityUnknown { raw_code });
        assert_eq!(
            decode_response(&encode_response(result.clone()).unwrap()),
            Ok(result)
        );
    }
}

#[test]
fn rollback_assessments_stages_and_closed_error_labels_roundtrip_without_secrets() {
    let assessments = [
        RollbackAssessment::NotNeeded,
        RollbackAssessment::Restored,
        RollbackAssessment::Unsafe,
        RollbackAssessment::Failed(Box::new(Error::PlatformIo {
            operation: boothop_core::PlatformOperation::Write,
            raw_code: 77,
        })),
    ];
    for assessment in assessments {
        let error = Error::FlowFailure {
            cause: Box::new(Error::RebootRejected),
            stages: vec![
                Stage::RollbackAttempted,
                Stage::RollbackRestored,
                Stage::RollbackUnsafe,
                Stage::RollbackFailed,
            ],
            residual_assessment: ResidualAssessment::Observed(Some(BootId(7))),
            rollback_assessment: assessment,
            diagnostics: vec![],
        };
        let encoded = encode_response(Err(error.clone())).unwrap();
        let text = std::str::from_utf8(&encoded[4..]).unwrap();
        for sensitive in ["secret\\identity", "OptionalData", "{8be4df61", "S-1-5-21"] {
            assert!(!text.contains(sensitive));
        }
        assert_eq!(decode_response(&encoded), Ok(Err(error)));
    }
    assert!(decode_response(&frame(
        r#"{"protocol_version":2,"result":{"Err":{"PlatformIo":{"operation":"secret_identity","raw_code":5}}}}"#
    ))
    .is_err());
}
#[test]
fn every_domain_error_and_nested_residual_roundtrip() {
    let errors = vec![
        Error::MalformedLoadOption,
        Error::MalformedDevicePath,
        Error::ResourceLimit,
        Error::UnsupportedFormat,
        Error::UnsupportedRecordVersion { found: u64::MAX },
        Error::UnsupportedIdentityComponent,
        Error::CorruptRecord,
        Error::IdentityMismatch,
        Error::UnexpectedOs,
        Error::TargetMissing,
        Error::NotConfigured,
        Error::BootNextConflict,
        Error::Busy,
        Error::ReadbackFailed,
        Error::RebootRejected,
        Error::NotUefi,
        Error::PrivilegeUnavailable,
        Error::PrivilegeEnableFailed { raw_code: 5 },
        Error::PrivilegeRestoreFailed { raw_code: 6 },
        Error::FirmwareReadFailed { raw_code: 7 },
        Error::FirmwareWriteFailed { raw_code: 8 },
        Error::BootNextUnavailable { raw_code: 9 },
        Error::ProtectedStoreViolation { raw_code: 10 },
        Error::StoreReplaceFailed { raw_code: 11 },
        Error::PlatformIo {
            operation: PlatformOperation::Ipc,
            raw_code: -1,
        },
        Error::StoreDurabilityUnknown { raw_code: 5 },
    ];
    for error in errors {
        for residual in [
            ResidualAssessment::NotChecked,
            ResidualAssessment::Observed(None),
            ResidualAssessment::Observed(Some(BootId(65535))),
            ResidualAssessment::ReadFailed(Box::new(Error::StoreDurabilityUnknown { raw_code: 5 })),
        ] {
            let nested = Error::FlowFailure {
                cause: Box::new(Error::FlowFailure {
                    cause: Box::new(error.clone()),
                    stages: report().stages,
                    residual_assessment: residual,
                    rollback_assessment: RollbackAssessment::NotNeeded,
                    diagnostics: report().diagnostics,
                }),
                stages: vec![Stage::ResidualPossible],
                residual_assessment: ResidualAssessment::NotChecked,
                rollback_assessment: RollbackAssessment::NotNeeded,
                diagnostics: vec![],
            };
            for result in [Err(error.clone()), Err(nested)] {
                assert_eq!(
                    decode_response(&encode_response(result.clone()).unwrap()),
                    Ok(result)
                );
            }
        }
    }
}
#[test]
fn every_report_shape_roundtrip_without_protected_data() {
    for record in [
        RecordDiagnostic::Missing,
        RecordDiagnostic::Ready {
            boot_id: BootId(0),
            os: Os::Linux,
        },
        report().record,
    ] {
        let mut r = report();
        r.record = record;
        let bytes = encode_response(Ok(r.clone())).unwrap();
        assert_eq!(decode_response(&bytes), Ok(Ok(r)));
        let text = std::str::from_utf8(&bytes[4..]).unwrap();
        for forbidden in [
            "identity",
            "digest",
            "optional_data",
            "OptionalData",
            "file_path",
            "TargetRecord",
        ] {
            assert!(!text.contains(forbidden));
        }
    }
}
#[test]
fn response_rejects_unknown_duplicate_and_malformed_results() {
    assert!(decode_response(&frame(r#"{"protocol_version":2,"result":{"Err":"Busy"}}"#)).is_ok());
    for json in [
        r#"{"protocol_version":2,"result":{"Err":"FutureError"}}"#,
        r#"{"protocol_version":2,"result":{"Err":{"Busy":null}}}"#,
        r#"{"protocol_version":2,"result":{"Err":{"StoreDurabilityUnknown":{"raw_code":5,"raw_code":6}}}}"#,
        r#"{"protocol_version":2,"result":{"Err":{"StoreDurabilityUnknown":{"raw_code":5,"path":"x"}}}}"#,
        r#"{"protocol_version":2,"result":{"Ok":{"candidates":[],"record":"Missing","stages":[],"diagnostics":[],"identity":"x"}}}"#,
        r#"{"protocol_version":2,"result":{"Ok":{"candidates":[],"record":"Missing","stages":["FutureStage"],"diagnostics":[]}}}"#,
    ] {
        assert!(decode_response(&frame(json)).is_err());
    }
}
#[test]
fn oversized_report_becomes_complete_resource_limit_within_total_budget() {
    let mut r = report();
    r.candidates[0].description_utf16 = vec![65535; 65536];
    assert_eq!(
        encode_response(Ok(r.clone())),
        Err(ProtocolError::ResourceLimit)
    );
    let bytes = budgeted_response(Ok(r), encode_hello().len()).unwrap();
    assert!(bytes.len() + encode_hello().len() <= 65536);
    let compact = decode_response(&bytes).unwrap().unwrap();
    assert_eq!(compact.stages, report().stages);
    assert_eq!(compact.diagnostics, []);
    assert!(compact.candidates[0].description_utf16.is_empty());
    assert!(budgeted_response(Err(Error::Busy), 65536).is_err());
    let normal = encode_response(Ok(report())).unwrap();
    let bounded = budgeted_response(Ok(report()), 65536 - normal.len() + 1).unwrap();
    assert!(matches!(decode_response(&bounded), Ok(Ok(_))));
    let mut inspect = report();
    inspect.stages.clear();
    inspect.candidates[0].description_utf16 = vec![65535; 65536];
    assert_eq!(
        decode_response(&budgeted_response(Ok(inspect), encode_hello().len()).unwrap()),
        Ok(Err(Error::ResourceLimit))
    );
}

#[test]
fn oversized_mutation_failure_keeps_stage_and_residual_evidence() {
    let error = Error::FlowFailure {
        cause: Box::new(Error::PlatformIo {
            operation: PlatformOperation::Write,
            raw_code: 32,
        }),
        stages: vec![
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::ResidualPossible,
        ],
        residual_assessment: ResidualAssessment::Observed(Some(BootId(7))),
        rollback_assessment: RollbackAssessment::NotNeeded,
        diagnostics: vec![EnumerationDiagnostic::DuplicateBootOrder(BootId(7)); 60_000],
    };
    let frame = budgeted_response(Err(error), encode_hello().len()).unwrap();
    assert!(frame.len() + encode_hello().len() <= MAX_BYTES);
    let Err(Error::FlowFailure {
        cause,
        stages,
        residual_assessment,
        diagnostics,
        ..
    }) = decode_response(&frame).unwrap()
    else {
        panic!("mutation evidence must remain terminal")
    };
    assert_eq!(
        *cause,
        Error::PlatformIo {
            operation: PlatformOperation::Write,
            raw_code: 32,
        }
    );
    assert_eq!(
        stages,
        [
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::ResidualPossible
        ]
    );
    assert_eq!(
        residual_assessment,
        ResidualAssessment::Observed(Some(BootId(7)))
    );
    assert!(diagnostics.is_empty());
}

#[test]
fn oversized_configure_failure_preserves_bounded_terminal_cause() {
    let error = Error::FlowFailure {
        cause: Box::new(Error::StoreDurabilityUnknown { raw_code: 28 }),
        stages: vec![Stage::TargetValidated],
        residual_assessment: ResidualAssessment::NotChecked,
        rollback_assessment: RollbackAssessment::NotNeeded,
        diagnostics: vec![EnumerationDiagnostic::DuplicateBootOrder(BootId(7)); 60_000],
    };
    let frame = budgeted_response(Err(error), encode_hello().len()).unwrap();
    assert!(frame.len() + encode_hello().len() <= MAX_BYTES);
    let Err(Error::FlowFailure {
        cause,
        stages,
        residual_assessment,
        diagnostics,
        ..
    }) = decode_response(&frame).unwrap()
    else {
        panic!("oversized configure failure must remain a domain failure")
    };
    assert_eq!(*cause, Error::StoreDurabilityUnknown { raw_code: 28 });
    assert_eq!(stages, [Stage::TargetValidated]);
    assert_eq!(residual_assessment, ResidualAssessment::NotChecked);
    assert!(diagnostics.is_empty());
}

#[test]
fn oversized_failure_preserves_reboot_rejected_cause_without_residual_fabrication() {
    let error = Error::FlowFailure {
        cause: Box::new(Error::RebootRejected),
        stages: vec![
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootRejected,
        ],
        residual_assessment: ResidualAssessment::Observed(None),
        rollback_assessment: RollbackAssessment::NotNeeded,
        diagnostics: vec![EnumerationDiagnostic::DuplicateBootOrder(BootId(7)); 60_000],
    };
    let frame = budgeted_response(Err(error), encode_hello().len()).unwrap();
    let Err(Error::FlowFailure {
        cause,
        stages,
        residual_assessment,
        diagnostics,
        ..
    }) = decode_response(&frame).unwrap()
    else {
        panic!("oversized reboot rejection must remain a domain failure")
    };
    assert_eq!(*cause, Error::RebootRejected);
    assert_eq!(
        stages,
        [
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootRejected
        ]
    );
    assert_eq!(residual_assessment, ResidualAssessment::Observed(None));
    assert!(diagnostics.is_empty());
}

#[test]
fn compaction_bounds_recursive_cause_and_preserves_nested_errno_evidence() {
    let error = Error::FlowFailure {
        cause: Box::new(Error::FlowFailure {
            cause: Box::new(Error::StoreDurabilityUnknown { raw_code: 5 }),
            stages: vec![Stage::TargetValidated],
            residual_assessment: ResidualAssessment::NotChecked,
            rollback_assessment: RollbackAssessment::NotNeeded,
            diagnostics: vec![],
        }),
        stages: vec![Stage::TargetValidated, Stage::BootNextVerified],
        residual_assessment: ResidualAssessment::ReadFailed(Box::new(
            Error::StoreDurabilityUnknown { raw_code: 28 },
        )),
        rollback_assessment: RollbackAssessment::NotNeeded,
        diagnostics: vec![EnumerationDiagnostic::DuplicateBootOrder(BootId(7)); 60_000],
    };
    let frame = budgeted_response(Err(error), encode_hello().len()).unwrap();
    let Err(Error::FlowFailure {
        cause,
        residual_assessment,
        diagnostics,
        ..
    }) = decode_response(&frame).unwrap()
    else {
        panic!("oversized nested failure must remain a domain failure")
    };
    assert_eq!(*cause, Error::ResourceLimit);
    assert_eq!(
        residual_assessment,
        ResidualAssessment::ReadFailed(Box::new(Error::StoreDurabilityUnknown { raw_code: 28 }))
    );
    assert!(diagnostics.is_empty());
}

#[test]
fn three_operations_roundtrip_and_switch_rejects_cached_id() {
    for request in [
        Request::Inspect,
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows,
        },
        Request::Switch { os: Os::Windows },
    ] {
        assert_eq!(
            decode_request(&encode_request(request).unwrap()),
            Ok(request)
        );
    }
    let json = br#"{"protocol_version":2,"request":{"Switch":{"os":"Windows","boot_id":7}}}"#;
    let mut frame = (json.len() as u32).to_le_bytes().to_vec();
    frame.extend(json);
    assert!(decode_request(&frame).is_err());
}
