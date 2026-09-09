use boothop_core::{
    DevicePathNodeKind, Error, FilePathNode, HardDriveNode, parse_device_path, parse_load_option,
};

const END_INSTANCE: [u8; 4] = [0x7f, 0x01, 0x04, 0x00];
const END_ENTIRE: [u8; 4] = [0x7f, 0xff, 0x04, 0x00];

fn node(node_type: u8, subtype: u8, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len() + 4).expect("synthetic node is small");
    let mut bytes = vec![node_type, subtype];
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn load_option(attributes: u32, description: &[u16], paths: &[u8], optional: &[u8]) -> Vec<u8> {
    let path_length = u16::try_from(paths.len()).expect("synthetic path list is small");
    let mut bytes = attributes.to_le_bytes().to_vec();
    bytes.extend_from_slice(&path_length.to_le_bytes());
    for code_unit in description {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(paths);
    bytes.extend_from_slice(optional);
    bytes
}

fn hard_drive_node() -> Vec<u8> {
    let mut payload = 3_u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
    payload.extend_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
    payload.extend(0_u8..16);
    payload.extend_from_slice(&[2, 2]);
    node(4, 1, &payload)
}

fn decode_hex(input: &str) -> Vec<u8> {
    let digits = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<Vec<_>>();
    let (pairs, remainder) = digits.as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let encoded = pair.iter().collect::<String>();
            u8::from_str_radix(&encoded, 16).expect("fixture contains hexadecimal bytes")
        })
        .collect()
}

#[test]
fn rejects_truncated_header() {
    assert_eq!(
        parse_load_option(&[1, 0, 0]),
        Err(Error::MalformedLoadOption)
    );
}

#[test]
fn parse_header_little_endian_unaligned() {
    let payload = load_option(0x4433_2211, &[], &[], &[0xaa]);
    let mut enclosing = vec![0xff];
    enclosing.extend_from_slice(&payload);
    let parsed = parse_load_option(&enclosing[1..]).unwrap();
    assert_eq!(parsed.attributes, 0x4433_2211);
    assert_eq!(parsed.optional_data, [0xaa]);
}

#[test]
fn parse_payload_over_limit() {
    assert_eq!(
        parse_load_option(&vec![0_u8; 1_048_577]),
        Err(Error::ResourceLimit)
    );
}

#[test]
fn parse_empty_and_unicode_description() {
    let empty = parse_load_option(&load_option(0, &[], &[], &[])).unwrap();
    let unicode = parse_load_option(&load_option(0, &[0x542f, 0x52a8], &[], &[])).unwrap();
    assert!(empty.description_utf16.is_empty());
    assert_eq!(unicode.description_utf16, [0x542f, 0x52a8]);
}

#[test]
fn parse_description_missing_nul() {
    let bytes = [0, 0, 0, 0, 0, 0, 0x41, 0x00];
    assert_eq!(parse_load_option(&bytes), Err(Error::MalformedLoadOption));
}

#[test]
fn parse_description_half_code_unit() {
    let bytes = [0, 0, 0, 0, 0, 0, 0x41];
    assert_eq!(parse_load_option(&bytes), Err(Error::MalformedLoadOption));
}

#[test]
fn parse_description_surrogate_pair() {
    let parsed = parse_load_option(&load_option(0, &[0xd83d, 0xde00], &[], &[])).unwrap();
    assert_eq!(parsed.description_utf16, [0xd83d, 0xde00]);
}

#[test]
fn parse_description_unpaired_surrogate() {
    assert_eq!(
        parse_load_option(&load_option(0, &[0xd83d], &[], &[])),
        Err(Error::MalformedLoadOption)
    );
}

#[test]
fn parse_empty_binary_odd_length_optional() {
    let parsed = parse_load_option(&load_option(0, &[], &[], &[0x00, 0xff, 0x7f])).unwrap();
    assert!(parsed.file_paths.is_empty());
    assert_eq!(parsed.optional_data, [0x00, 0xff, 0x7f]);
}

#[test]
fn path_list_length_overflow_rejected() {
    let bytes = [0, 0, 0, 0, 0xff, 0xff, 0, 0];
    assert_eq!(parse_load_option(&bytes), Err(Error::MalformedLoadOption));
}

#[test]
fn parse_multiple_complete_path_elements() {
    let mut paths = END_ENTIRE.to_vec();
    paths.extend_from_slice(&node(1, 2, &[0xaa]));
    paths.extend_from_slice(&END_ENTIRE);
    let parsed = parse_load_option(&load_option(0, &[], &paths, &[])).unwrap();
    assert_eq!(parsed.file_paths.len(), 2);
    assert_eq!(parsed.file_path_list_length, 13);
}

#[test]
fn parse_zero_path_list() {
    let parsed = parse_load_option(&load_option(0, &[], &[], &[])).unwrap();
    assert_eq!(parsed.file_path_list_length, 0);
    assert!(parsed.file_paths.is_empty());
}

#[test]
fn parse_path_list_trailing_partial_header() {
    let mut paths = END_ENTIRE.to_vec();
    paths.extend_from_slice(&[1, 2]);
    assert_eq!(
        parse_load_option(&load_option(0, &[], &paths, &[])),
        Err(Error::MalformedDevicePath)
    );
}

#[test]
fn parse_unknown_node_preserved() {
    let mut bytes = node(1, 2, &[0xaa, 0xbb]);
    bytes.extend_from_slice(&END_ENTIRE);
    let parsed = parse_device_path(&bytes).unwrap();
    let unknown = &parsed.instances[0].nodes[0];
    assert_eq!(
        (unknown.node_type, unknown.subtype, unknown.length),
        (1, 2, 6)
    );
    assert_eq!(unknown.payload, [0xaa, 0xbb]);
    assert_eq!(unknown.kind, DevicePathNodeKind::Unknown);
}

#[test]
fn truncated_node_rejected() {
    assert_eq!(
        parse_device_path(&[1, 2, 6, 0, 0xaa]),
        Err(Error::MalformedDevicePath)
    );
}

#[test]
fn parse_zero_or_short_node_length() {
    assert_eq!(
        parse_device_path(&[1, 2, 0, 0]),
        Err(Error::MalformedDevicePath)
    );
    assert_eq!(
        parse_device_path(&[1, 2, 3, 0]),
        Err(Error::MalformedDevicePath)
    );
}

#[test]
fn parse_multiple_instances() {
    let mut bytes = node(1, 2, &[0xaa]);
    bytes.extend_from_slice(&END_INSTANCE);
    bytes.extend_from_slice(&node(2, 3, &[]));
    bytes.extend_from_slice(&END_ENTIRE);
    let parsed = parse_device_path(&bytes).unwrap();
    assert_eq!(parsed.instances.len(), 2);
    assert_eq!(parsed.instances[0].nodes.len(), 2);
    assert_eq!(parsed.instances[1].nodes.len(), 2);
    assert_eq!(
        parsed.instances[0].nodes[1].kind,
        DevicePathNodeKind::EndInstance
    );
    assert_eq!(
        parsed.instances[1].nodes[1].kind,
        DevicePathNodeKind::EndEntire
    );
}

#[test]
fn parse_end_entire() {
    let parsed = parse_device_path(&END_ENTIRE).unwrap();
    assert_eq!(parsed.instances.len(), 1);
    assert_eq!(parsed.instances[0].nodes.len(), 1);
    assert_eq!(
        parsed.instances[0].nodes[0].kind,
        DevicePathNodeKind::EndEntire
    );
}

#[test]
fn parse_bad_end_length() {
    assert_eq!(
        parse_device_path(&[0x7f, 0xff, 5, 0, 0]),
        Err(Error::MalformedDevicePath)
    );
}

#[test]
fn parse_missing_end_entire() {
    assert_eq!(
        parse_device_path(&node(1, 2, &[])),
        Err(Error::MalformedDevicePath)
    );
}

#[test]
fn parse_end_instance_without_final_path() {
    assert_eq!(
        parse_device_path(&END_INSTANCE),
        Err(Error::MalformedDevicePath)
    );
}

#[test]
fn parse_unknown_end_subtype_rejected() {
    assert_eq!(
        parse_device_path(&[0x7f, 0x02, 4, 0]),
        Err(Error::MalformedDevicePath)
    );
}

#[test]
fn parse_end_entire_rejects_trailing_bytes() {
    let mut bytes = END_ENTIRE.to_vec();
    bytes.push(0);
    assert_eq!(parse_device_path(&bytes), Err(Error::MalformedDevicePath));
}

#[test]
fn parse_hd_fields_little_endian() {
    let mut bytes = hard_drive_node();
    bytes.extend_from_slice(&END_ENTIRE);
    let parsed = parse_device_path(&bytes).unwrap();
    assert_eq!(
        parsed.instances[0].nodes[0].kind,
        DevicePathNodeKind::HardDrive(HardDriveNode {
            partition_number: 3,
            partition_start_lba: 0x1122_3344_5566_7788,
            partition_size_lba: 0x0102_0304_0506_0708,
            partition_signature_uefi_bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,],
            mbr_type: 2,
            signature_type: 2,
        })
    );
}

#[test]
fn parse_hd_wrong_length() {
    let mut bytes = node(4, 1, &[0; 37]);
    bytes.extend_from_slice(&END_ENTIRE);
    assert_eq!(parse_device_path(&bytes), Err(Error::MalformedDevicePath));
}

#[test]
fn parse_filepath_unicode() {
    let mut bytes = node(4, 4, &[0x2f, 0x54, 0xa8, 0x52, 0, 0]);
    bytes.extend_from_slice(&END_ENTIRE);
    let parsed = parse_device_path(&bytes).unwrap();
    assert_eq!(
        parsed.instances[0].nodes[0].kind,
        DevicePathNodeKind::FilePath(FilePathNode {
            path_utf16: vec![0x542f, 0x52a8]
        })
    );
}

#[test]
fn parse_empty_filepath() {
    let mut bytes = node(4, 4, &[0, 0]);
    bytes.extend_from_slice(&END_ENTIRE);
    let parsed = parse_device_path(&bytes).unwrap();
    assert_eq!(
        parsed.instances[0].nodes[0].kind,
        DevicePathNodeKind::FilePath(FilePathNode {
            path_utf16: Vec::new()
        })
    );
}

#[test]
fn parse_filepath_odd_length() {
    let mut bytes = node(4, 4, &[0, 0, 0]);
    bytes.extend_from_slice(&END_ENTIRE);
    assert_eq!(parse_device_path(&bytes), Err(Error::MalformedDevicePath));
}

#[test]
fn parse_filepath_embedded_nul() {
    let mut bytes = node(4, 4, &[0x41, 0, 0, 0, 0x42, 0]);
    bytes.extend_from_slice(&END_ENTIRE);
    assert_eq!(parse_device_path(&bytes), Err(Error::MalformedDevicePath));
}

#[test]
fn invalid_utf16_path_rejected() {
    let mut bytes = node(4, 4, &[0x3d, 0xd8, 0, 0]);
    bytes.extend_from_slice(&END_ENTIRE);
    assert_eq!(parse_device_path(&bytes), Err(Error::MalformedDevicePath));
}

#[test]
fn parse_optional_all_bytes_preserved() {
    let optional = [0, 0xff, 0x7f, 0x00, 0x80];
    let parsed = parse_load_option(&load_option(0, &[], &END_ENTIRE, &optional)).unwrap();
    assert_eq!(parsed.optional_data, optional);
}

#[test]
fn parse_optional_not_confused_with_second_path() {
    let mut paths = END_ENTIRE.to_vec();
    paths.extend_from_slice(&END_ENTIRE);
    let optional = [0x7f, 0xff, 4, 0, 1, 2, 3];
    let parsed = parse_load_option(&load_option(0, &[], &paths, &optional)).unwrap();
    assert_eq!(parsed.file_paths.len(), 2);
    assert_eq!(parsed.optional_data, optional);
}

#[test]
fn parse_complete_option_only() {
    let parsed = parse_load_option(&load_option(7, &[0x0041], &END_ENTIRE, &[0xde, 0xad]))
        .expect("complete option parses");
    assert_eq!(parsed.attributes, 7);
    assert_eq!(parsed.description_utf16, [0x0041]);
    assert_eq!(parsed.file_path_list_length, 4);
    assert_eq!(parsed.file_paths.len(), 1);
    assert_eq!(parsed.optional_data, [0xde, 0xad]);
}

#[test]
fn parse_error_has_no_partial_target() {
    let mut malformed_path = node(1, 2, &[]);
    malformed_path.extend_from_slice(&[0x7f, 0xff, 5, 0, 0]);
    assert_eq!(
        parse_load_option(&load_option(7, &[0x0041], &malformed_path, &[0xde, 0xad])),
        Err(Error::MalformedDevicePath)
    );
}

#[test]
fn parse_synthetic_task1_shape_fixture() {
    let bytes = decode_hex(include_str!(
        "../../../fixtures/uefi/synthetic/task1-shape.hex"
    ));

    let parsed = parse_load_option(&bytes).expect("public synthetic fixture parses");

    assert_eq!(parsed.attributes, 1);
    assert_eq!(parsed.file_path_list_length, 94);
    assert_eq!(parsed.file_paths.len(), 1);
    assert_eq!(parsed.file_paths[0].instances.len(), 1);
    assert_eq!(parsed.file_paths[0].instances[0].nodes.len(), 3);
    assert!(matches!(
        parsed.file_paths[0].instances[0].nodes[0].kind,
        DevicePathNodeKind::HardDrive(_)
    ));
    assert!(matches!(
        parsed.file_paths[0].instances[0].nodes[1].kind,
        DevicePathNodeKind::FilePath(_)
    ));
    assert_eq!(
        parsed.file_paths[0].instances[0].nodes[2].kind,
        DevicePathNodeKind::EndEntire
    );
    assert_eq!(parsed.optional_data, [0x00, 0xff, 0x80, 0x7f]);
}
