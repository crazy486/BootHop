use boothop_core::{
    BootId, CanonicalDevicePathNode, CanonicalEndEntireNode, CanonicalFilePathNode,
    CanonicalHardDriveNode, CanonicalIdentity, Error, OpaqueAlgorithm, OpaqueExactV1, Os,
    RecordState, TargetRecord, decode_record, encode_record, expected_target,
};

const DIGEST_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const EMPTY_DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn target(byte_length: u64, digest: [u8; 32]) -> TargetRecord {
    TargetRecord {
        os: Os::Linux,
        boot_id: BootId(u16::MAX),
        identity: CanonicalIdentity {
            file_path_list_length: 94,
            nodes: [
                CanonicalDevicePathNode::HardDrive(CanonicalHardDriveNode {
                    node_type: 4,
                    subtype: 1,
                    length: 42,
                    partition_number: u32::MAX,
                    partition_start_lba: 9_007_199_254_740_993,
                    partition_size_lba: 131_072,
                    partition_signature_uefi_bytes: [
                        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    ],
                    mbr_type: 2,
                    signature_type: 2,
                }),
                CanonicalDevicePathNode::FilePath(CanonicalFilePathNode {
                    node_type: 4,
                    subtype: 4,
                    length: 48,
                    path_utf16: "\\EFI\\BOOT\\BOOTX64.EFI".encode_utf16().collect(),
                    terminator: 0,
                }),
                CanonicalDevicePathNode::EndEntire(CanonicalEndEntireNode {
                    node_type: 127,
                    subtype: 255,
                    length: 4,
                }),
            ],
            optional_data: OpaqueExactV1 {
                algorithm: OpaqueAlgorithm::Sha256,
                byte_length,
                digest,
            },
        },
    }
}

fn populated_target() -> TargetRecord {
    target(32, core::array::from_fn(|index| index as u8))
}

fn valid_json() -> String {
    format!(
        concat!(
            r#"{{"version":1,"target":{{"os":"Linux","boot_id":65535,"identity":{{"kind":"CanonicalIdentity","version":1,"file_path_list_length":94,"nodes":["#,
            r#"{{"kind":"HardDrive","type":4,"subtype":1,"length":42,"partition_number":4294967295,"partition_start_lba":9007199254740993,"partition_size_lba":131072,"partition_signature_uefi_bytes":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"mbr_type":2,"signature_type":2}},"#,
            r#"{{"kind":"FilePath","type":4,"subtype":4,"length":48,"path_utf16":[92,69,70,73,92,66,79,79,84,92,66,79,79,84,88,54,52,46,69,70,73],"terminator":0}},"#,
            r#"{{"kind":"EndEntire","type":127,"subtype":255,"length":4}}],"optional_data":{{"kind":"OpaqueExact","version":1,"algorithm":"Sha256","byte_length":32,"digest":"{}"}}}}}}}}"#,
        ),
        DIGEST_HEX
    )
}

#[test]
fn unknown_record_version_stops_before_payload_decode() {
    let result = decode_record(br#"{"version":999,"target":{}}"#);

    assert!(matches!(
        result,
        Err(Error::UnsupportedRecordVersion { found: 999 })
    ));
}

#[test]
fn expected_target_is_always_the_other_operating_system() {
    assert_eq!(expected_target(Os::Linux), Os::Windows);
    assert_eq!(expected_target(Os::Windows), Os::Linux);
}

#[test]
fn record_v1_full_width_roundtrip_uses_the_exact_literal_shape() {
    let expected = valid_json();

    let encoded = encode_record(&populated_target()).expect("valid record encodes");

    assert_eq!(encoded, expected.as_bytes());
    assert_eq!(decode_record(&encoded), Ok(populated_target()));
    assert!(expected.contains("9007199254740993"));
    assert!(!expected.contains("optional_data_raw"));
}

#[test]
fn empty_optional_digest_roundtrips_without_inventing_original_data() {
    let empty_digest = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    let record = target(0, empty_digest);

    let encoded = encode_record(&record).expect("empty opaque component encodes");

    assert_eq!(decode_record(&encoded), Ok(record));
    assert!(
        String::from_utf8(encoded)
            .unwrap()
            .contains(EMPTY_DIGEST_HEX)
    );
}

#[test]
fn missing_record_state_is_explicit() {
    let missing = RecordState::Missing;
    assert!(matches!(missing, RecordState::Missing));
}

#[test]
fn unknown_identity_components_fail_closed_as_unsupported() {
    for json in [
        valid_json().replacen("CanonicalIdentity", "FutureIdentity", 1),
        valid_json().replacen(
            r#""version":1,"file_path_list_length"#,
            r#""version":2,"file_path_list_length"#,
            1,
        ),
        valid_json().replacen("HardDrive", "FutureNode", 1),
        valid_json().replacen("OpaqueExact", "FutureOpaque", 1),
        valid_json().replacen(r#""version":1,"algorithm"#, r#""version":2,"algorithm"#, 1),
        valid_json().replacen("Sha256", "FutureHash", 1),
    ] {
        assert_eq!(
            decode_record(json.as_bytes()),
            Err(Error::UnsupportedIdentityComponent)
        );
    }
}

#[test]
fn future_identity_marker_precedes_changed_identity_shape() {
    let future_kind = valid_json()
        .replacen("CanonicalIdentity", "FutureIdentity", 1)
        .replacen(
            r#""file_path_list_length":94"#,
            r#""future_identity_payload":true"#,
            1,
        );
    let future_version = valid_json()
        .replacen(
            r#""kind":"CanonicalIdentity","version":1"#,
            r#""kind":"CanonicalIdentity","version":2"#,
            1,
        )
        .replacen(
            r#""file_path_list_length":94"#,
            r#""future_identity_payload":true"#,
            1,
        );

    for json in [future_kind, future_version] {
        assert_eq!(
            decode_record(json.as_bytes()),
            Err(Error::UnsupportedIdentityComponent)
        );
    }
}

#[test]
fn future_node_marker_precedes_changed_node_shape() {
    let json = valid_json()
        .replacen("HardDrive", "FutureNode", 1)
        .replacen(
            r#""partition_number":4294967295"#,
            r#""future_node_payload":true"#,
            1,
        );

    assert_eq!(
        decode_record(json.as_bytes()),
        Err(Error::UnsupportedIdentityComponent)
    );
}

#[test]
fn future_opaque_marker_precedes_changed_opaque_shape() {
    let future_kind = valid_json()
        .replacen("OpaqueExact", "FutureOpaque", 1)
        .replacen(r#""byte_length":32"#, r#""future_opaque_payload":true"#, 1);
    let future_version = valid_json()
        .replacen(
            r#""kind":"OpaqueExact","version":1"#,
            r#""kind":"OpaqueExact","version":2"#,
            1,
        )
        .replacen(r#""byte_length":32"#, r#""future_opaque_payload":true"#, 1);

    for json in [future_kind, future_version] {
        assert_eq!(
            decode_record(json.as_bytes()),
            Err(Error::UnsupportedIdentityComponent)
        );
    }
}

#[test]
fn future_algorithm_marker_precedes_changed_opaque_shape() {
    let json = valid_json().replacen("Sha256", "FutureHash", 1).replacen(
        r#""byte_length":32"#,
        r#""future_algorithm_payload":true"#,
        1,
    );

    assert_eq!(
        decode_record(json.as_bytes()),
        Err(Error::UnsupportedIdentityComponent)
    );
}

#[test]
fn future_identity_kind_precedes_wrong_typed_sibling_version() {
    let json = valid_json()
        .replacen("CanonicalIdentity", "FutureIdentity", 1)
        .replacen(
            r#""version":1,"file_path_list_length"#,
            r#""version":{"future":2},"file_path_list_length"#,
            1,
        );

    assert_eq!(
        decode_record(json.as_bytes()),
        Err(Error::UnsupportedIdentityComponent)
    );
}

#[test]
fn future_opaque_discriminator_precedes_later_marker_and_body_types() {
    let future_kind = valid_json()
        .replacen("OpaqueExact", "FutureOpaque", 1)
        .replacen(
            r#""version":1,"algorithm":"Sha256""#,
            r#""version":"v2","algorithm":7"#,
            1,
        );
    let future_version = valid_json().replacen(
        r#""kind":"OpaqueExact","version":1,"algorithm":"Sha256""#,
        r#""kind":"OpaqueExact","version":2,"algorithm":7"#,
        1,
    );
    let future_algorithm = valid_json().replacen("Sha256", "FutureHash", 1).replacen(
        r#""byte_length":32"#,
        r#""byte_length":{"future":32}"#,
        1,
    );

    for json in [future_kind, future_version, future_algorithm] {
        assert_eq!(
            decode_record(json.as_bytes()),
            Err(Error::UnsupportedIdentityComponent)
        );
    }
}

#[test]
fn known_or_invalid_marker_fields_remain_corrupt() {
    for json in [
        valid_json().replacen(
            r#""kind":"CanonicalIdentity""#,
            r#""kind":"CanonicalIdentity","kind":"CanonicalIdentity""#,
            1,
        ),
        valid_json().replacen(
            r#""kind":"HardDrive""#,
            r#""kind":"HardDrive","kind":"HardDrive""#,
            1,
        ),
        valid_json().replacen(
            r#""kind":"OpaqueExact""#,
            r#""kind":"OpaqueExact","kind":"OpaqueExact""#,
            1,
        ),
        valid_json().replacen(
            r#""kind":"CanonicalIdentity""#,
            r#""kind":"CanonicalIdentity","future_identity_field":true"#,
            1,
        ),
        valid_json().replacen(r#""kind":"CanonicalIdentity""#, r#""kind":7"#, 1),
        valid_json().replacen(r#""kind":"HardDrive""#, r#""kind":7"#, 1),
        valid_json().replacen(
            r#""version":1,"file_path_list_length"#,
            r#""version":"v1","file_path_list_length"#,
            1,
        ),
        valid_json().replacen(
            r#""kind":"OpaqueExact","version":1"#,
            r#""kind":"OpaqueExact","version":"v1""#,
            1,
        ),
        valid_json().replacen(r#""algorithm":"Sha256""#, r#""algorithm":7"#, 1),
        valid_json().replacen(
            r#""kind":"CanonicalIdentity""#,
            r#""kind":"FutureIdentity","kind":"FutureIdentity""#,
            1,
        ),
        valid_json().replacen(
            r#""kind":"OpaqueExact""#,
            r#""kind":"FutureOpaque","algorithm":"FutureHash","algorithm":"FutureHash""#,
            1,
        ),
    ] {
        assert_eq!(decode_record(json.as_bytes()), Err(Error::CorruptRecord));
    }
}

#[test]
fn record_input_over_one_mib_is_rejected_without_truncation() {
    let oversized = format!(
        r#"{{"version":1,"target":{{"padding":"{}"}}}}"#,
        "x".repeat(1_048_576)
    );

    assert_eq!(
        decode_record(oversized.as_bytes()),
        Err(Error::ResourceLimit)
    );
}

#[test]
fn malformed_envelopes_are_corrupt_not_missing() {
    for bytes in [
        &b""[..],
        &br#"{}"#[..],
        &br#"{"version":"1","target":{}}"#[..],
        &br#"{"version":1,"target":{"os":"Linux"}"#[..],
        &br#"{"version":1,"target":null}"#[..],
    ] {
        assert_eq!(decode_record(bytes), Err(Error::CorruptRecord));
    }
}

#[test]
fn unknown_version_does_not_require_the_v1_target_shape() {
    assert_eq!(
        decode_record(br#"{"version":18446744073709551615,"target":"future","extra":1}"#),
        Err(Error::UnsupportedRecordVersion { found: u64::MAX })
    );
}

#[test]
fn duplicate_or_unknown_record_fields_are_rejected() {
    let duplicate =
        valid_json().replacen(r#""boot_id":65535"#, r#""boot_id":65535,"boot_id":7"#, 1);
    let duplicate_component = valid_json().replacen(
        r#""algorithm":"Sha256"#,
        r#""algorithm":"Sha256","algorithm":"Sha256"#,
        1,
    );
    let unknown_root = valid_json().replacen(r#""version":1"#, r#""version":1,"future":false"#, 1);
    let unknown_target =
        valid_json().replacen(r#""boot_id":65535"#, r#""future":false,"boot_id":65535"#, 1);
    let unknown_node =
        valid_json().replacen(r#""mbr_type":2"#, r#""future":false,"mbr_type":2"#, 1);
    let unknown_opaque = valid_json().replacen(
        r#""byte_length":32"#,
        r#""future":false,"byte_length":32"#,
        1,
    );

    for json in [
        duplicate,
        duplicate_component,
        unknown_root,
        unknown_target,
        unknown_node,
        unknown_opaque,
    ] {
        assert_eq!(decode_record(json.as_bytes()), Err(Error::CorruptRecord));
    }
}

#[test]
fn missing_wrong_type_fractional_negative_and_overflow_fields_are_corrupt() {
    for json in [
        valid_json().replacen(r#","boot_id":65535"#, "", 1),
        valid_json().replacen(r#""boot_id":65535"#, r#""boot_id":"65535""#, 1),
        valid_json().replacen(r#""boot_id":65535"#, r#""boot_id":1.5"#, 1),
        valid_json().replacen(r#""boot_id":65535"#, r#""boot_id":-1"#, 1),
        valid_json().replacen(r#""boot_id":65535"#, r#""boot_id":65536"#, 1),
        valid_json().replacen("9007199254740993", "18446744073709551616", 1),
        valid_json().replacen(r#""os":"Linux""#, r#""os":"linux""#, 1),
    ] {
        assert_eq!(decode_record(json.as_bytes()), Err(Error::CorruptRecord));
    }
}

#[test]
fn missing_identity_component_is_corrupt_not_unsupported() {
    let missing_optional = valid_json().replacen(
        &format!(
            r#","optional_data":{{"kind":"OpaqueExact","version":1,"algorithm":"Sha256","byte_length":32,"digest":"{DIGEST_HEX}"}}"#
        ),
        "",
        1,
    );

    assert_eq!(
        decode_record(missing_optional.as_bytes()),
        Err(Error::CorruptRecord)
    );
}

#[test]
fn bad_digest_length_encoding_or_case_is_corrupt() {
    for bad_digest in [
        &DIGEST_HEX[..62],
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1g",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    ] {
        let json = valid_json().replace(DIGEST_HEX, bad_digest);
        assert_eq!(decode_record(json.as_bytes()), Err(Error::CorruptRecord));
    }
}

#[test]
fn canonical_node_constants_order_and_derived_lengths_are_revalidated() {
    let mut reordered_value: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
    reordered_value["target"]["identity"]["nodes"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let reordered = serde_json::to_string(&reordered_value).unwrap();
    for json in [
        valid_json().replacen(
            r#""file_path_list_length":94"#,
            r#""file_path_list_length":93"#,
            1,
        ),
        valid_json().replacen(
            r#""kind":"HardDrive","type":4"#,
            r#""kind":"HardDrive","type":3"#,
            1,
        ),
        valid_json().replacen(
            r#""partition_number":4294967295"#,
            r#""partition_number":0"#,
            1,
        ),
        valid_json().replacen(
            r#""partition_size_lba":131072"#,
            r#""partition_size_lba":0"#,
            1,
        ),
        valid_json().replacen("9007199254740993", "18446744073709551615", 1),
        valid_json().replacen(
            r#""length":48,"path_utf16"#,
            r#""length":46,"path_utf16"#,
            1,
        ),
        valid_json().replacen(r#""path_utf16":[92"#, r#""path_utf16":[47"#, 1),
        valid_json().replacen(r#""terminator":0"#, r#""terminator":1"#, 1),
        valid_json().replacen(
            r#""kind":"EndEntire","type":127"#,
            r#""kind":"EndEntire","type":126"#,
            1,
        ),
        reordered,
    ] {
        assert_eq!(decode_record(json.as_bytes()), Err(Error::CorruptRecord));
    }
}

#[test]
fn opaque_length_invariants_are_revalidated() {
    let wrong_empty_digest = valid_json().replacen(r#""byte_length":32"#, r#""byte_length":0"#, 1);
    let impossible_length =
        valid_json().replacen(r#""byte_length":32"#, r#""byte_length":1048577"#, 1);

    assert_eq!(
        decode_record(wrong_empty_digest.as_bytes()),
        Err(Error::CorruptRecord)
    );
    assert_eq!(
        decode_record(impossible_length.as_bytes()),
        Err(Error::CorruptRecord)
    );
}

#[test]
fn encode_rejects_invalid_in_memory_identity() {
    let mut record = populated_target();
    record.identity.file_path_list_length -= 1;

    assert_eq!(encode_record(&record), Err(Error::CorruptRecord));
}
