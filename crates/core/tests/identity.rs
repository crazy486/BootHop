use boothop_core::{
    BootId, CanonicalDevicePathNode, Classification, DevicePathNodeKind, Error, LoadOption, Os,
    TargetRecord, canonicalize, classify, parse_load_option, validate_target,
};

const END_ENTIRE: [u8; 4] = [0x7f, 0xff, 0x04, 0x00];
const SIGNATURE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

fn node(node_type: u8, subtype: u8, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len() + 4).expect("synthetic node is small");
    let mut bytes = vec![node_type, subtype];
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn hard_drive_node(
    partition_number: u32,
    partition_start_lba: u64,
    partition_size_lba: u64,
    signature: [u8; 16],
) -> Vec<u8> {
    let mut payload = partition_number.to_le_bytes().to_vec();
    payload.extend_from_slice(&partition_start_lba.to_le_bytes());
    payload.extend_from_slice(&partition_size_lba.to_le_bytes());
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(&[2, 2]);
    node(4, 1, &payload)
}

fn file_path_node(path: &[u16]) -> Vec<u8> {
    let mut payload = Vec::new();
    for unit in path {
        payload.extend_from_slice(&unit.to_le_bytes());
    }
    payload.extend_from_slice(&0_u16.to_le_bytes());
    node(4, 4, &payload)
}

fn load_option_bytes(
    attributes: u32,
    description: &[u16],
    paths: &[u8],
    optional: &[u8],
) -> Vec<u8> {
    let path_length = u16::try_from(paths.len()).expect("synthetic path list is small");
    let mut bytes = attributes.to_le_bytes().to_vec();
    bytes.extend_from_slice(&path_length.to_le_bytes());
    for unit in description {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(paths);
    bytes.extend_from_slice(optional);
    bytes
}

fn supported_bytes(
    description: &[u16],
    partition_number: u32,
    partition_start_lba: u64,
    partition_size_lba: u64,
    signature: [u8; 16],
    path: &[u16],
    optional: &[u8],
) -> Vec<u8> {
    let mut paths = hard_drive_node(
        partition_number,
        partition_start_lba,
        partition_size_lba,
        signature,
    );
    paths.extend_from_slice(&file_path_node(path));
    paths.extend_from_slice(&END_ENTIRE);
    load_option_bytes(1, description, &paths, optional)
}

fn supported(description: &[u16], optional: &[u8]) -> LoadOption {
    parse_load_option(&supported_bytes(
        description,
        3,
        0x1000,
        0x20_000,
        SIGNATURE,
        &"\\EFI\\BOOT\\BOOTX64.EFI"
            .encode_utf16()
            .collect::<Vec<_>>(),
        optional,
    ))
    .expect("synthetic supported option parses")
}

fn target(option: &LoadOption) -> TargetRecord {
    TargetRecord {
        os: Os::Linux,
        boot_id: BootId(7),
        identity: canonicalize(option).expect("supported option canonicalizes"),
    }
}

#[test]
fn research_fixture_identity_relationships_are_conservative() {
    let before = supported(
        &"Linux".encode_utf16().collect::<Vec<_>>(),
        &[0, 0xff, 0x80],
    );
    let renamed = supported(
        &"Renamed".encode_utf16().collect::<Vec<_>>(),
        &[0, 0xff, 0x80],
    );
    let different_partition = parse_load_option(&supported_bytes(
        &"Linux".encode_utf16().collect::<Vec<_>>(),
        4,
        0x1000,
        0x20_000,
        SIGNATURE,
        &"\\EFI\\BOOT\\BOOTX64.EFI"
            .encode_utf16()
            .collect::<Vec<_>>(),
        &[0, 0xff, 0x80],
    ))
    .unwrap();
    let ambiguous = supported(
        &"Windows Boot Manager".encode_utf16().collect::<Vec<_>>(),
        &[],
    );

    assert_eq!(
        canonicalize(&before).unwrap(),
        canonicalize(&renamed).unwrap()
    );
    assert_ne!(
        canonicalize(&before).unwrap(),
        canonicalize(&different_partition).unwrap()
    );
    assert_eq!(classify(&ambiguous), Classification::NeedsConfirmation);
}

#[test]
fn short_gpt_filepath_supported_and_reusable_number_matches() {
    let current = supported(&[], &[0xde, 0xad]);
    assert_eq!(validate_target(&target(&current), &current), Ok(()));
}

#[test]
fn valid_description_and_hidden_changes_preserve_identity() {
    let before = supported(&"Before".encode_utf16().collect::<Vec<_>>(), &[1, 2]);
    let mut after = supported(&"After".encode_utf16().collect::<Vec<_>>(), &[1, 2]);
    after.attributes = 0x0000_0009;
    assert_eq!(canonicalize(&before), canonicalize(&after));
}

#[test]
fn unknown_multi_instance_extra_and_split_paths_are_rejected() {
    let good = supported(&[], &[]);

    let mut unknown = good.clone();
    unknown.file_paths[0].instances[0].nodes[0].node_type = 1;
    unknown.file_paths[0].instances[0].nodes[0].subtype = 2;
    unknown.file_paths[0].instances[0].nodes[0].kind = DevicePathNodeKind::Unknown;
    assert_eq!(canonicalize(&unknown), Err(Error::UnsupportedFormat));

    let mut multiple_instances = good.clone();
    let second = multiple_instances.file_paths[0].instances[0].clone();
    multiple_instances.file_paths[0].instances.push(second);
    assert_eq!(
        canonicalize(&multiple_instances),
        Err(Error::UnsupportedFormat)
    );

    let mut extra_path = good.clone();
    extra_path.file_paths.push(extra_path.file_paths[0].clone());
    assert_eq!(canonicalize(&extra_path), Err(Error::UnsupportedFormat));

    let mut split_path = good;
    let file_node = split_path.file_paths[0].instances[0].nodes[1].clone();
    split_path.file_paths[0].instances[0]
        .nodes
        .insert(2, file_node);
    assert_eq!(canonicalize(&split_path), Err(Error::UnsupportedFormat));
}

#[test]
fn hard_drive_fields_and_geometry_are_validated() {
    let good = supported(&[], &[]);
    let saved = target(&good);
    let mut changed_signature = SIGNATURE;
    changed_signature[0] ^= 1;
    for (number, start, size, signature) in [
        (4, 0x1000, 0x20_000, SIGNATURE),
        (3, 0x1001, 0x20_000, SIGNATURE),
        (3, 0x1000, 0x20_001, SIGNATURE),
        (3, 0x1000, 0x20_000, changed_signature),
    ] {
        let changed = parse_load_option(&supported_bytes(
            &[],
            number,
            start,
            size,
            signature,
            &"\\EFI\\BOOT\\BOOTX64.EFI"
                .encode_utf16()
                .collect::<Vec<_>>(),
            &[],
        ))
        .unwrap();
        assert_eq!(
            validate_target(&saved, &changed),
            Err(Error::IdentityMismatch)
        );
    }

    for (number, size, signature) in [(0, 1, [1; 16]), (1, 0, [1; 16]), (1, 1, [0; 16])] {
        let invalid = parse_load_option(&supported_bytes(
            &[],
            number,
            0x1000,
            size,
            signature,
            &"\\EFI\\BOOT\\BOOTX64.EFI"
                .encode_utf16()
                .collect::<Vec<_>>(),
            &[],
        ))
        .unwrap();
        assert_eq!(canonicalize(&invalid), Err(Error::UnsupportedFormat));
    }

    let overflow = parse_load_option(&supported_bytes(
        &[],
        1,
        u64::MAX,
        1,
        [1; 16],
        &"\\EFI\\BOOT\\BOOTX64.EFI"
            .encode_utf16()
            .collect::<Vec<_>>(),
        &[],
    ))
    .unwrap();
    assert_eq!(canonicalize(&overflow), Err(Error::UnsupportedFormat));

    for trailer in [[1, 2], [2, 0]] {
        let mut invalid = supported(&[], &[]);
        let node = &mut invalid.file_paths[0].instances[0].nodes[0];
        node.payload[36..38].copy_from_slice(&trailer);
        let DevicePathNodeKind::HardDrive(hd) = &mut node.kind else {
            panic!("fixture has hard-drive node")
        };
        hd.mbr_type = trailer[0];
        hd.signature_type = trailer[1];
        assert_eq!(canonicalize(&invalid), Err(Error::UnsupportedFormat));
    }
}

#[test]
fn typed_nodes_must_match_preserved_payload_and_headers() {
    let mut forged = supported(&[], &[]);
    forged.file_paths[0].instances[0].nodes[0].payload[0] ^= 1;
    assert_eq!(canonicalize(&forged), Err(Error::UnsupportedFormat));

    let mut bad_length = supported(&[], &[]);
    bad_length.file_paths[0].instances[0].nodes[1].length += 2;
    assert_eq!(canonicalize(&bad_length), Err(Error::UnsupportedFormat));

    let mut bad_list_length = supported(&[], &[]);
    bad_list_length.file_path_list_length += 1;
    assert_eq!(
        canonicalize(&bad_list_length),
        Err(Error::UnsupportedFormat)
    );

    let mut bad_end = supported(&[], &[]);
    bad_end.file_paths[0].instances[0].nodes[2].payload.push(0);
    assert_eq!(canonicalize(&bad_end), Err(Error::UnsupportedFormat));
}

#[test]
fn strict_absolute_path_rules_are_enforced() {
    for path in [
        "relative\\loader.efi",
        "\\",
        "\\EFI\\",
        "\\EFI\\\\loader.efi",
        "\\EFI\\.\\loader.efi",
        "\\EFI\\..\\loader.efi",
        "\\EFI/loader.efi",
    ] {
        let parsed = parse_load_option(&supported_bytes(
            &[],
            3,
            0x1000,
            0x20_000,
            [1; 16],
            &path.encode_utf16().collect::<Vec<_>>(),
            &[],
        ))
        .unwrap();
        assert_eq!(
            canonicalize(&parsed),
            Err(Error::UnsupportedFormat),
            "{path}"
        );
    }
}

#[test]
fn absolute_unicode_path_is_preserved_and_path_changes_mismatch() {
    let unicode = parse_load_option(&supported_bytes(
        &[],
        3,
        0x1000,
        0x20_000,
        [1; 16],
        &"\\EFI\\启动.efi".encode_utf16().collect::<Vec<_>>(),
        &[],
    ))
    .unwrap();
    let saved = target(&unicode);

    for path in ["\\EFI\\启动2.efi", "\\efi\\启动.efi"] {
        let changed = parse_load_option(&supported_bytes(
            &[],
            3,
            0x1000,
            0x20_000,
            [1; 16],
            &path.encode_utf16().collect::<Vec<_>>(),
            &[],
        ))
        .unwrap();
        assert_eq!(
            validate_target(&saved, &changed),
            Err(Error::IdentityMismatch)
        );
    }
}

#[test]
fn malformed_description_and_load_attributes_are_rejected() {
    let mut malformed_description = supported(&[], &[]);
    malformed_description.description_utf16 = vec![0xd800];
    assert_eq!(
        canonicalize(&malformed_description),
        Err(Error::UnsupportedFormat)
    );

    for attributes in [0, 8, 3, 0x10, 0x8000_0001] {
        let mut option = supported(&[], &[]);
        option.attributes = attributes;
        assert_eq!(canonicalize(&option), Err(Error::UnsupportedFormat));
        assert_eq!(classify(&option), Classification::Unsupported);
    }
}

#[test]
fn sha256_known_answers_cover_empty_and_nonempty_data() {
    let empty = canonicalize(&supported(&[], &[])).unwrap();
    assert_eq!(empty.file_path_list_length, 94);
    let CanonicalDevicePathNode::HardDrive(hard_drive) = &empty.nodes[0] else {
        panic!("first component is hard-drive")
    };
    assert_eq!(hard_drive.partition_number, 3);
    assert_eq!(hard_drive.partition_start_lba, 0x1000);
    assert_eq!(hard_drive.partition_size_lba, 0x20_000);
    assert_eq!(hard_drive.partition_signature_uefi_bytes, SIGNATURE);
    let CanonicalDevicePathNode::FilePath(file_path) = &empty.nodes[1] else {
        panic!("second component is file-path")
    };
    assert_eq!(
        file_path.path_utf16,
        "\\EFI\\BOOT\\BOOTX64.EFI"
            .encode_utf16()
            .collect::<Vec<_>>()
    );
    assert!(matches!(
        empty.nodes[2],
        CanonicalDevicePathNode::EndEntire(_)
    ));
    assert_eq!(
        empty.optional_data.digest,
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ]
    );
    assert_eq!(
        canonicalize(&supported(&[], b"abc"))
            .unwrap()
            .optional_data
            .digest,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}

#[test]
fn opaque_non_utf16_can_register() {
    let option = supported(&[], &[0xff, 0x00, 0xd8, 0x7f]);
    assert_eq!(canonicalize(&option).unwrap().optional_data.byte_length, 4);
}

#[test]
fn same_buffer_identity_deterministic() {
    let option = supported(&[], &[0xff, 0x00, 0xd8, 0x7f]);
    assert_eq!(canonicalize(&option), canonicalize(&option));
}

#[test]
fn opaque_exact_change_rejected() {
    let before = supported(&[], &[0x10, 0x20, 0, 0x30]);
    let saved = target(&before);
    for optional in [
        vec![0x11, 0x20, 0, 0x30],
        vec![0x10, 0x20, 0, 0x31],
        vec![0x10, 0x20, 1, 0x30],
        vec![0x10, 0x20, 0, 0x30, 0],
        vec![0x10, 0x20, 0],
        Vec::new(),
    ] {
        assert_eq!(
            validate_target(&saved, &supported(&[], &optional)),
            Err(Error::IdentityMismatch)
        );
    }
    let empty_saved = target(&supported(&[], &[]));
    assert_eq!(
        validate_target(&empty_saved, &supported(&[], &[0])),
        Err(Error::IdentityMismatch)
    );
}

#[test]
fn id_reuse_mismatch_stops_but_os_and_number_do_not_change_identity_check() {
    let original = supported(&[], &[1]);
    let mut saved = target(&original);
    saved.os = Os::Windows;
    saved.boot_id = BootId(u16::MAX);
    assert_eq!(validate_target(&saved, &original), Ok(()));

    let replacement = supported(&[], &[2]);
    assert_eq!(
        validate_target(&saved, &replacement),
        Err(Error::IdentityMismatch)
    );
}

#[test]
fn name_never_produces_known_classification() {
    for name in ["Windows Boot Manager", "ubuntu", "GRUB", "only candidate"] {
        let option = supported(&name.encode_utf16().collect::<Vec<_>>(), &[]);
        assert_eq!(classify(&option), Classification::NeedsConfirmation);
    }
}

#[test]
fn matching_digest_cannot_bypass_malformed_outer_or_path_structure() {
    let good = supported(&[], &[9, 8, 7]);
    let saved = target(&good);

    let mut bad_outer = good.clone();
    bad_outer.attributes = 0;
    assert_eq!(
        validate_target(&saved, &bad_outer),
        Err(Error::UnsupportedFormat)
    );

    let mut bad_path = good;
    bad_path.file_paths[0].instances[0].nodes[1].node_type = 1;
    assert_eq!(
        validate_target(&saved, &bad_path),
        Err(Error::UnsupportedFormat)
    );
}
