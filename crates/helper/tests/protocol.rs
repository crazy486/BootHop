use boothop_core::{BootId, Os, Request};
use boothop_core::{
    Candidate, Classification, EnumerationDiagnostic, Error, RecordDiagnostic, Report,
    ResidualAssessment, Stage,
};
use boothop_helper::protocol::*;
use boothop_helper::protocol::{decode_request, encode_request};

fn frame(json: &str) -> Vec<u8> {
    let mut frame = (json.len() as u32).to_le_bytes().to_vec();
    frame.extend(json.as_bytes());
    frame
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
                    r#"{{"protocol_version":1,"request":{request}}}"#
                )))
                .is_err(),
                "{extra}"
            );
        }
        assert!(
            decode_request(&frame(&format!(
                r#"{{"protocol_version":1,"request":"Inspect","{extra}":7}}"#
            )))
            .is_err()
        );
    }
    for json in [
        r#"{"protocol_version":1,"protocol_version":1,"request":"Inspect"}"#,
        r#"{"protocol_version":1,"request":"Inspect","request":"Inspect"}"#,
        r#"{"protocol_version":1,"request":{"Switch":{"os":"Windows","os":"Linux"}}}"#,
        r#"{"protocol_version":1,"request":{"Configure":{"os":"Windows","boot_id":7,"boot_id":8}}}"#,
        r#"{"protocol_version":1,"request":{"Switch":{"os":"Other"}}}"#,
        r#"{"protocol_version":"1","request":"Inspect"}"#,
        r#"{"protocol_version":1,"request":{"Configure":{"os":"Windows","boot_id":65536}}}"#,
        r#"{"protocol_version":1,"request":{"Configure":{"os":"Windows","boot_id":-1}}}"#,
        r#"{"protocol_version":1,"request":"Delete"}"#,
        r#"{"protocol_version":1,"request":null}"#,
    ] {
        assert!(decode_request(&frame(json)).is_err(), "{json}");
    }
}
#[test]
fn version_truncation_trailing_and_frame_limit_fail_closed() {
    assert_eq!(
        decode_request(&frame(r#"{"protocol_version":2,"request":"Inspect"}"#)),
        Err(ProtocolError::Version)
    );
    let bytes = encode_request(Request::Inspect).unwrap();
    for n in 0..bytes.len() {
        assert!(decode_request(&bytes[..n]).is_err());
    }
    assert!(decode_request(&[bytes.clone(), vec![0]].concat()).is_err());
    assert!(decode_request(&frame(r#"{"protocol_version":1,"request":"Inspect"} {}"#)).is_err());
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
        r#"{"protocol_version":2,"hello":true}"#,
        r#"{"protocol_version":1,"hello":false}"#,
        r#"{"protocol_version":1,"hello":true,"hello":true}"#,
        r#"{"protocol_version":1,"hello":true,"path":"/tmp"}"#,
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
        Error::PlatformIo {
            operation: "ipc".into(),
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
                    diagnostics: report().diagnostics,
                }),
                stages: vec![Stage::ResidualPossible],
                residual_assessment: ResidualAssessment::NotChecked,
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
    for json in [
        r#"{"protocol_version":1,"result":{"Err":"FutureError"}}"#,
        r#"{"protocol_version":2,"result":{"Err":"Busy"}}"#,
        r#"{"protocol_version":1,"result":{"Err":{"StoreDurabilityUnknown":{"raw_code":5,"raw_code":6}}}}"#,
        r#"{"protocol_version":1,"result":{"Err":{"StoreDurabilityUnknown":{"raw_code":5,"path":"x"}}}}"#,
        r#"{"protocol_version":1,"result":{"Ok":{"candidates":[],"record":"Missing","stages":[],"diagnostics":[],"identity":"x"}}}"#,
        r#"{"protocol_version":1,"result":{"Ok":{"candidates":[],"record":"Missing","stages":["FutureStage"],"diagnostics":[]}}}"#,
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
    assert_eq!(decode_response(&bytes), Ok(Err(Error::ResourceLimit)));
    assert!(budgeted_response(Err(Error::Busy), 65536).is_err());
    let normal = encode_response(Ok(report())).unwrap();
    assert_eq!(
        decode_response(&budgeted_response(Ok(report()), 65536 - normal.len() + 1).unwrap()),
        Ok(Err(Error::ResourceLimit))
    );
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
    let json = br#"{"protocol_version":1,"request":{"Switch":{"os":"Windows","boot_id":7}}}"#;
    let mut frame = (json.len() as u32).to_le_bytes().to_vec();
    frame.extend(json);
    assert!(decode_request(&frame).is_err());
}
