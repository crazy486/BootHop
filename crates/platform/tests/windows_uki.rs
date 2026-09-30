use boothop_core::{
    CanonicalDevicePathNode, CanonicalEndEntireNode, CanonicalFilePathNode, CanonicalHardDriveNode,
    CanonicalIdentity, OpaqueAlgorithm, OpaqueExactV1,
};
use boothop_platform::windows::uki::{
    EFI_SYSTEM_PARTITION_TYPE_GUID_UEFI_BYTES, EfiVolume, FileHandleIdentity, FileIdentitySnapshot,
    FileReadError, GptPartition, MAX_UKI_BYTES, NativeEfiCalls, NativeEfiVolume,
    NativeEfiVolumeAdapter, NativeFixedUkiRead, NativePartitionScheme, ReadOnlyEfiVolumes,
    UkiPreflightError, VolumeEnumerationError, preflight_uki,
};

const FILE_PATH: &str = r"\EFI\BootHop\arch.efi";

#[derive(Clone, Debug, Eq, PartialEq)]
struct FakeVolumes {
    volumes: Vec<EfiVolume>,
    bytes: Result<Vec<u8>, FileReadError>,
    reads: std::cell::Cell<usize>,
}

impl ReadOnlyEfiVolumes for FakeVolumes {
    fn existing_efi_volumes(&self) -> Result<Vec<EfiVolume>, VolumeEnumerationError> {
        Ok(self.volumes.clone())
    }

    fn read_fixed_uki(
        &self,
        volume_id: u64,
        expected_partition: GptPartition,
    ) -> Result<Vec<u8>, FileReadError> {
        assert_eq!(volume_id, 9);
        assert_eq!(expected_partition, partition());
        self.reads.set(self.reads.get() + 1);
        self.bytes.clone()
    }
}

fn identity() -> CanonicalIdentity {
    let path: Vec<u16> = FILE_PATH.encode_utf16().collect();
    let file_length = ((path.len() + 1) * 2 + 4) as u16;
    CanonicalIdentity {
        file_path_list_length: 42 + file_length + 4,
        nodes: [
            CanonicalDevicePathNode::HardDrive(CanonicalHardDriveNode {
                node_type: 4,
                subtype: 1,
                length: 42,
                partition_number: 3,
                partition_start_lba: 2048,
                partition_size_lba: 500_000,
                partition_signature_uefi_bytes: [0x11; 16],
                mbr_type: 2,
                signature_type: 2,
            }),
            CanonicalDevicePathNode::FilePath(CanonicalFilePathNode {
                node_type: 4,
                subtype: 4,
                length: file_length,
                path_utf16: path,
                terminator: 0,
            }),
            CanonicalDevicePathNode::EndEntire(CanonicalEndEntireNode {
                node_type: 0x7f,
                subtype: 0xff,
                length: 4,
            }),
        ],
        optional_data: OpaqueExactV1 {
            algorithm: OpaqueAlgorithm::Sha256,
            byte_length: 0,
            digest: [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ],
        },
    }
}

fn partition() -> GptPartition {
    GptPartition {
        number: 3,
        starting_lba: 2048,
        size_lba: 500_000,
        partition_guid_uefi_bytes: [0x11; 16],
    }
}

fn volume(partition: GptPartition) -> EfiVolume {
    EfiVolume { id: 9, partition }
}

// A small structurally valid PE32+ image containing non-empty UKI sections.
fn valid_uki() -> Vec<u8> {
    valid_uki_at(0x80)
}

fn valid_uki_at(pe_offset: usize) -> Vec<u8> {
    let names = [b".linux".as_slice(), b".osrel", b".cmdline", b".initrd"];
    let section_count = names.len();
    let optional_size = 0xf0;
    let table = pe_offset + 4 + 20 + optional_size;
    let raw_start = table + section_count * 40;
    let mut image = vec![0_u8; raw_start + section_count];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    image[pe_offset + 4..pe_offset + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
    image[pe_offset + 6..pe_offset + 8].copy_from_slice(&(section_count as u16).to_le_bytes());
    image[pe_offset + 20..pe_offset + 22].copy_from_slice(&(optional_size as u16).to_le_bytes());
    image[pe_offset + 24..pe_offset + 26].copy_from_slice(&0x20b_u16.to_le_bytes());
    for (i, name) in names.iter().enumerate() {
        let header = table + i * 40;
        image[header..header + name.len()].copy_from_slice(name);
        image[header + 16..header + 20].copy_from_slice(&1_u32.to_le_bytes());
        image[header + 20..header + 24].copy_from_slice(&((raw_start + i) as u32).to_le_bytes());
        image[raw_start + i] = 0x41 + i as u8;
    }
    image
}

fn fake(bytes: Result<Vec<u8>, FileReadError>) -> FakeVolumes {
    FakeVolumes {
        volumes: vec![volume(partition())],
        bytes,
        reads: std::cell::Cell::new(0),
    }
}

#[test]
fn accepts_only_the_matching_partition_and_fixed_path_with_a_well_formed_uki() {
    let volumes = fake(Ok(valid_uki()));
    assert_eq!(preflight_uki(&volumes, &identity()), Ok(()));
    assert_eq!(volumes.reads.get(), 1);
}

#[test]
fn rejects_zero_or_multiple_matching_volumes_before_reading() {
    let mut absent = fake(Ok(valid_uki()));
    absent.volumes.clear();
    assert_eq!(
        preflight_uki(&absent, &identity()),
        Err(UkiPreflightError::NoMatchingVolume)
    );
    assert_eq!(absent.reads.get(), 0);

    let mut ambiguous = fake(Ok(valid_uki()));
    ambiguous.volumes.push(volume(partition()));
    assert_eq!(
        preflight_uki(&ambiguous, &identity()),
        Err(UkiPreflightError::AmbiguousVolumes)
    );
    assert_eq!(ambiguous.reads.get(), 0);
}

#[test]
fn rejects_wrong_partition_number_guid_or_geometry() {
    for changed in [
        GptPartition {
            number: 4,
            ..partition()
        },
        GptPartition {
            partition_guid_uefi_bytes: [0x22; 16],
            ..partition()
        },
        GptPartition {
            starting_lba: 4096,
            ..partition()
        },
        GptPartition {
            size_lba: 500_001,
            ..partition()
        },
    ] {
        let mut volumes = fake(Ok(valid_uki()));
        volumes.volumes[0].partition = changed;
        assert_eq!(
            preflight_uki(&volumes, &identity()),
            Err(UkiPreflightError::NoMatchingVolume)
        );
        assert_eq!(volumes.reads.get(), 0);
    }
}

#[test]
fn rejects_a_non_fixed_file_path_without_enumerating_volumes() {
    let mut target = identity();
    let CanonicalDevicePathNode::FilePath(path) = &mut target.nodes[1] else {
        unreachable!();
    };
    path.path_utf16 = r"\EFI\BootHop\other.efi".encode_utf16().collect();
    let volumes = fake(Ok(valid_uki()));
    assert_eq!(
        preflight_uki(&volumes, &target),
        Err(UkiPreflightError::UnsupportedIdentity)
    );
    assert_eq!(volumes.reads.get(), 0);
}

#[test]
fn rejects_zero_guid_overflowing_geometry_and_invalid_optional_data() {
    let mut zero_guid = identity();
    let CanonicalDevicePathNode::HardDrive(disk) = &mut zero_guid.nodes[0] else {
        unreachable!();
    };
    disk.partition_signature_uefi_bytes = [0; 16];

    let mut overflowing_geometry = identity();
    let CanonicalDevicePathNode::HardDrive(disk) = &mut overflowing_geometry.nodes[0] else {
        unreachable!();
    };
    disk.partition_start_lba = u64::MAX - 10;
    disk.partition_size_lba = 11;

    let mut non_empty_optional_data = identity();
    non_empty_optional_data.optional_data.byte_length = 1;

    let mut inconsistent_optional_data = identity();
    inconsistent_optional_data.optional_data.digest[0] ^= 1;

    for target in [
        zero_guid,
        overflowing_geometry,
        non_empty_optional_data,
        inconsistent_optional_data,
    ] {
        let volumes = fake(Ok(valid_uki()));
        assert_eq!(
            preflight_uki(&volumes, &target),
            Err(UkiPreflightError::UnsupportedIdentity)
        );
        assert_eq!(volumes.reads.get(), 0);
    }
}

#[test]
fn rejects_missing_or_unsupported_file() {
    for error in [
        FileReadError::Missing,
        FileReadError::Unsupported,
        FileReadError::Failed,
    ] {
        let volumes = fake(Err(error));
        assert_eq!(
            preflight_uki(&volumes, &identity()),
            Err(UkiPreflightError::FileUnavailable)
        );
    }
}

#[test]
fn rejects_corrupt_pe_headers_and_truncated_section_data() {
    let mut bad_signature = valid_uki();
    bad_signature[0] = b'X';
    assert_eq!(
        preflight_uki(&fake(Ok(bad_signature)), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );

    let mut truncated_section = valid_uki();
    let pe_offset = 0x80;
    let optional_size = 0xf0;
    let first_section = pe_offset + 4 + 20 + optional_size;
    truncated_section[first_section + 20..first_section + 24]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        preflight_uki(&fake(Ok(truncated_section)), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );

    let mut zero_machine = valid_uki();
    zero_machine[0x84..0x86].copy_from_slice(&0_u16.to_le_bytes());
    assert_eq!(
        preflight_uki(&fake(Ok(zero_machine)), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );

    let mut invalid_name_padding = valid_uki();
    invalid_name_padding[first_section + 7] = b'X';
    assert_eq!(
        preflight_uki(&fake(Ok(invalid_name_padding)), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );

    let mut unsupported_machine = valid_uki();
    unsupported_machine[0x84..0x86].copy_from_slice(&0xaa64_u16.to_le_bytes());
    assert_eq!(
        preflight_uki(&fake(Ok(unsupported_machine)), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );
}

#[test]
fn rejects_pe32_optional_headers_for_x86_64_uki() {
    let mut pe32 = valid_uki();
    pe32[0x98..0x9a].copy_from_slice(&0x10b_u16.to_le_bytes());
    assert_eq!(
        preflight_uki(&fake(Ok(pe32)), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );
}

#[test]
fn rejects_pe_signature_offsets_inside_the_dos_header() {
    assert_eq!(
        preflight_uki(&fake(Ok(valid_uki_at(0x20))), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );
}

#[test]
fn rejects_section_data_overlapping_pe_headers_or_section_table() {
    let mut overlapping_section = valid_uki();
    let section_table_end = 0x80 + 4 + 20 + 0xf0 + 4 * 40;
    let first_section = 0x80 + 4 + 20 + 0xf0;
    overlapping_section[first_section + 20..first_section + 24]
        .copy_from_slice(&((section_table_end - 1) as u32).to_le_bytes());
    assert_eq!(
        preflight_uki(&fake(Ok(overlapping_section)), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );
}

#[test]
fn rejects_uki_bytes_over_the_fixed_limit_before_pe_parsing() {
    let oversized = vec![0_u8; MAX_UKI_BYTES + 1];
    assert_eq!(
        preflight_uki(&fake(Ok(oversized)), &identity()),
        Err(UkiPreflightError::ImageTooLarge)
    );
}

#[test]
fn rejects_missing_empty_or_duplicate_required_uki_sections() {
    let valid = valid_uki();
    let pe_offset = 0x80;
    let first_section = pe_offset + 4 + 20 + 0xf0;

    let mut missing_linux = valid.clone();
    missing_linux[first_section..first_section + 8].fill(0);
    assert_eq!(
        preflight_uki(&fake(Ok(missing_linux)), &identity()),
        Err(UkiPreflightError::MalformedUki)
    );

    let mut empty_osrel = valid.clone();
    let osrel = first_section + 40;
    empty_osrel[osrel + 16..osrel + 20].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(
        preflight_uki(&fake(Ok(empty_osrel)), &identity()),
        Err(UkiPreflightError::MalformedUki)
    );

    let mut duplicate_cmdline = valid;
    let cmdline = first_section + 2 * 40;
    duplicate_cmdline[cmdline..cmdline + 8].copy_from_slice(b".linux\0\0");
    assert_eq!(
        preflight_uki(&fake(Ok(duplicate_cmdline)), &identity()),
        Err(UkiPreflightError::MalformedUki)
    );
}

fn declaration_region<'a>(source: &'a str, declaration: &str, next: &str) -> &'a str {
    let after_declaration = source
        .split_once(declaration)
        .map(|(_, tail)| tail)
        .expect("declaration exists");
    after_declaration
        .split_once(next)
        .map(|(region, _)| region)
        .expect("following declaration exists")
}

#[test]
fn native_trait_region_does_not_leak_past_crlf_boundary() {
    let source = "pub trait NativeEfiCalls {\r\n    fn read_fixed_uki(&self);\r\n}\r\npub struct NativeEfiVolumeAdapter { path_utf16: Vec<u16> }\r\n";
    let native_trait = declaration_region(
        source,
        "pub trait NativeEfiCalls {",
        "pub struct NativeEfiVolumeAdapter",
    );

    assert!(native_trait.contains("read_fixed_uki"));
    assert!(!native_trait.contains("path_utf16"));
}

#[test]
fn the_volume_boundary_only_offers_shared_reference_reads() {
    let boundary = include_str!("../src/windows/uki.rs");
    let trait_body = declaration_region(
        boundary,
        "pub trait ReadOnlyEfiVolumes {",
        "pub fn uses_fixed_uki_path",
    );
    assert!(trait_body.contains("&self"));
    assert!(trait_body.contains("read_fixed_uki"));
    assert!(
        !["write", "mount", "assign_drive_letter", "delete"]
            .iter()
            .any(|operation| trait_body.contains(operation))
    );

    let native_trait = declaration_region(
        boundary,
        "pub trait NativeEfiCalls {",
        "pub struct NativeEfiVolumeAdapter",
    );
    assert!(native_trait.contains("enumerate_existing_efi_volumes"));
    assert!(native_trait.contains("read_fixed_uki"));
    let normalized_native_trait = native_trait.replace("\r\n", "\n");
    assert!(normalized_native_trait.contains(
        "fn read_fixed_uki(\n        &self,\n        volume_id: u64,\n        expected_partition: GptPartition,\n        max_bytes: usize,\n    ) -> Result<NativeFixedUkiRead, FileReadError>;"
    ));
    assert!(!native_trait.contains("path_utf16"));
    assert!(
        ![
            "mount",
            "drive_letter",
            "write",
            "delete",
            "SetVolumeMountPoint"
        ]
        .iter()
        .any(|operation| native_trait.contains(operation))
    );
}

#[derive(Clone)]
struct FakeNativeCalls {
    volumes: Vec<NativeEfiVolume>,
    read: Result<NativeFixedUkiRead, FileReadError>,
    requested: std::rc::Rc<std::cell::RefCell<Vec<(u64, GptPartition, usize)>>>,
    enumeration_calls: std::rc::Rc<std::cell::Cell<usize>>,
    second_snapshot: Option<Vec<NativeEfiVolume>>,
    enumeration_fails: bool,
}

impl NativeEfiCalls for FakeNativeCalls {
    fn enumerate_existing_efi_volumes(
        &self,
    ) -> Result<Vec<NativeEfiVolume>, VolumeEnumerationError> {
        let call = self.enumeration_calls.get();
        self.enumeration_calls.set(call + 1);
        if self.enumeration_fails {
            return Err(VolumeEnumerationError::Failed);
        }
        if call == 1
            && let Some(snapshot) = &self.second_snapshot
        {
            return Ok(snapshot.clone());
        }
        Ok(self.volumes.clone())
    }

    fn read_fixed_uki(
        &self,
        volume_id: u64,
        expected_partition: GptPartition,
        max_bytes: usize,
    ) -> Result<NativeFixedUkiRead, FileReadError> {
        self.requested
            .borrow_mut()
            .push((volume_id, expected_partition, max_bytes));
        self.read.clone()
    }
}

fn native_volume(sector_size: u32, id: u64) -> NativeEfiVolume {
    NativeEfiVolume {
        id,
        partition_scheme: NativePartitionScheme::Gpt,
        partition_number: 3,
        starting_offset_bytes: 2048 * sector_size as u64,
        size_bytes: 500_000 * sector_size as u64,
        logical_sector_size: sector_size,
        partition_guid_uefi_bytes: [0x11; 16],
        partition_type_guid_uefi_bytes: EFI_SYSTEM_PARTITION_TYPE_GUID_UEFI_BYTES,
    }
}

fn stable_read(bytes: Vec<u8>) -> NativeFixedUkiRead {
    let identity = FileIdentitySnapshot {
        identity: Some(FileHandleIdentity {
            volume_serial_number: 0x1234,
            file_id: [7; 16],
        }),
        size: bytes.len() as u64,
        is_regular_file: true,
        is_reparse_point: false,
    };
    NativeFixedUkiRead {
        volume_id: 9,
        partition: partition(),
        before: identity,
        after: identity,
        bytes,
    }
}

fn native_fake(sector_size: u32, bytes: Vec<u8>) -> FakeNativeCalls {
    FakeNativeCalls {
        volumes: vec![native_volume(sector_size, 9)],
        read: Ok(stable_read(bytes)),
        requested: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
        enumeration_calls: std::rc::Rc::new(std::cell::Cell::new(0)),
        second_snapshot: None,
        enumeration_fails: false,
    }
}

#[test]
fn native_adapter_normalizes_512_and_4096_sector_partitions() {
    for sector_size in [512, 4096] {
        let calls = native_fake(sector_size, valid_uki());
        let adapter = NativeEfiVolumeAdapter::new(calls.clone());
        assert_eq!(preflight_uki(&adapter, &identity()), Ok(()));
        assert_eq!(calls.requested.borrow().len(), 1);
        assert_eq!(calls.requested.borrow()[0].2, MAX_UKI_BYTES);
    }
}

#[test]
fn native_adapter_fails_closed_for_non_esp_bad_sector_and_duplicate_volumes() {
    let calls = native_fake(512, valid_uki());
    let mut volume = calls.volumes[0];
    volume.partition_scheme = NativePartitionScheme::Mbr;
    volume.partition_type_guid_uefi_bytes = [0x55; 16];
    let non_esp = FakeNativeCalls {
        volumes: vec![volume],
        ..calls.clone()
    };
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(non_esp.clone()), &identity()),
        Err(UkiPreflightError::NoMatchingVolume)
    );
    assert!(non_esp.requested.borrow().is_empty());

    let mut non_gpt = calls.clone();
    non_gpt.volumes[0].partition_scheme = NativePartitionScheme::Unknown;
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(non_gpt.clone()), &identity()),
        Err(UkiPreflightError::NoMatchingVolume)
    );
    assert!(non_gpt.requested.borrow().is_empty());

    let mut invalid_sector = calls.clone();
    invalid_sector.volumes[0].logical_sector_size = 768;
    assert_eq!(
        preflight_uki(
            &NativeEfiVolumeAdapter::new(invalid_sector.clone()),
            &identity()
        ),
        Err(UkiPreflightError::NoMatchingVolume)
    );
    assert!(invalid_sector.requested.borrow().is_empty());

    let mut duplicate = calls;
    duplicate.volumes.push(native_volume(512, 10));
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(duplicate.clone()), &identity()),
        Err(UkiPreflightError::AmbiguousVolumes)
    );
    assert!(duplicate.requested.borrow().is_empty());

    let mut none = native_fake(512, valid_uki());
    none.volumes.clear();
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(none.clone()), &identity()),
        Err(UkiPreflightError::NoMatchingVolume)
    );
    assert!(none.requested.borrow().is_empty());
}

#[test]
fn native_adapter_rejects_stale_volume_id_or_unstable_and_unsupported_file_identity() {
    let calls = native_fake(512, valid_uki());
    let mut stale_read = stable_read(valid_uki());
    stale_read.partition.partition_guid_uefi_bytes = [0x22; 16];
    let stale = FakeNativeCalls {
        read: Ok(stale_read),
        ..calls.clone()
    };
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(stale.clone()), &identity()),
        Err(UkiPreflightError::FileUnavailable)
    );

    let mut reused_id = stable_read(valid_uki());
    reused_id.volume_id = 10;
    let reused = FakeNativeCalls {
        read: Ok(reused_id),
        ..calls.clone()
    };
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(reused), &identity()),
        Err(UkiPreflightError::FileUnavailable)
    );

    let mut changed = stable_read(valid_uki());
    changed.after.identity.as_mut().unwrap().file_id[0] ^= 1;
    let changed_file = FakeNativeCalls {
        read: Ok(changed),
        ..calls.clone()
    };
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(changed_file), &identity()),
        Err(UkiPreflightError::FileUnavailable)
    );

    let mut reparse = stable_read(valid_uki());
    reparse.before.is_reparse_point = true;
    let reparse_file = FakeNativeCalls {
        read: Ok(reparse),
        ..calls.clone()
    };
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(reparse_file), &identity()),
        Err(UkiPreflightError::FileUnavailable)
    );

    let mut changed_serial = stable_read(valid_uki());
    changed_serial
        .after
        .identity
        .as_mut()
        .unwrap()
        .volume_serial_number += 1;
    assert_eq!(
        preflight_uki(
            &NativeEfiVolumeAdapter::new(FakeNativeCalls {
                read: Ok(changed_serial),
                ..calls.clone()
            }),
            &identity()
        ),
        Err(UkiPreflightError::FileUnavailable)
    );

    let mut after_reparse = stable_read(valid_uki());
    after_reparse.after.is_reparse_point = true;
    assert_eq!(
        preflight_uki(
            &NativeEfiVolumeAdapter::new(FakeNativeCalls {
                read: Ok(after_reparse),
                ..calls.clone()
            }),
            &identity()
        ),
        Err(UkiPreflightError::FileUnavailable)
    );

    let mut changed_size = stable_read(valid_uki());
    changed_size.after.size -= 1;
    assert_eq!(
        preflight_uki(
            &NativeEfiVolumeAdapter::new(FakeNativeCalls {
                read: Ok(changed_size),
                ..calls.clone()
            }),
            &identity()
        ),
        Err(UkiPreflightError::FileUnavailable)
    );
}

#[test]
fn native_adapter_rejects_volume_disappearance_or_reuse_before_opening_the_file() {
    let mut same_partition_new_id = native_volume(512, 10);
    same_partition_new_id.partition_number = 3;
    let duplicate_invalid_id = NativeEfiVolume {
        id: 9,
        partition_scheme: NativePartitionScheme::Unknown,
        ..native_volume(512, 9)
    };
    for second_snapshot in [
        vec![],
        vec![NativeEfiVolume {
            starting_offset_bytes: 2049 * 512,
            ..native_volume(512, 9)
        }],
        vec![native_volume(512, 9), same_partition_new_id],
        vec![native_volume(512, 9), duplicate_invalid_id],
    ] {
        let calls = native_fake(512, valid_uki());
        let stale = FakeNativeCalls {
            second_snapshot: Some(second_snapshot),
            ..calls.clone()
        };
        assert_eq!(
            preflight_uki(&NativeEfiVolumeAdapter::new(stale.clone()), &identity()),
            Err(UkiPreflightError::FileUnavailable)
        );
        assert!(stale.requested.borrow().is_empty());
    }
}

#[test]
fn native_adapter_reports_enumeration_errors_and_zero_byte_files() {
    let calls = native_fake(512, valid_uki());
    let failed_enumeration = FakeNativeCalls {
        enumeration_fails: true,
        ..calls.clone()
    };
    assert_eq!(
        preflight_uki(
            &NativeEfiVolumeAdapter::new(failed_enumeration.clone()),
            &identity()
        ),
        Err(UkiPreflightError::VolumeEnumerationFailed)
    );
    assert!(failed_enumeration.requested.borrow().is_empty());

    let zero_byte_file = FakeNativeCalls {
        read: Ok(stable_read(vec![])),
        ..calls
    };
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(zero_byte_file), &identity()),
        Err(UkiPreflightError::MalformedPe)
    );
}

#[test]
fn native_adapter_rejects_short_and_oversized_reads() {
    let calls = native_fake(512, valid_uki());
    let mut short = stable_read(valid_uki());
    short.bytes.pop();
    let short_read = FakeNativeCalls {
        read: Ok(short),
        ..calls.clone()
    };
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(short_read), &identity()),
        Err(UkiPreflightError::FileUnavailable)
    );

    let mut too_large = stable_read(vec![0; MAX_UKI_BYTES + 1]);
    too_large.before.size = (MAX_UKI_BYTES + 1) as u64;
    too_large.after.size = (MAX_UKI_BYTES + 1) as u64;
    let oversized = FakeNativeCalls {
        read: Ok(too_large),
        ..calls
    };
    assert_eq!(
        preflight_uki(&NativeEfiVolumeAdapter::new(oversized), &identity()),
        Err(UkiPreflightError::ImageTooLarge)
    );
}

#[test]
fn native_adapter_rejects_unavailable_zero_file_identity() {
    let calls = native_fake(512, valid_uki());
    for file_identity in [
        None,
        Some(FileHandleIdentity {
            volume_serial_number: 0x1234,
            file_id: [0; 16],
        }),
        Some(FileHandleIdentity {
            volume_serial_number: 0,
            file_id: [7; 16],
        }),
    ] {
        let mut unavailable = stable_read(valid_uki());
        unavailable.before.identity = file_identity;
        unavailable.after.identity = file_identity;
        assert_eq!(
            preflight_uki(
                &NativeEfiVolumeAdapter::new(FakeNativeCalls {
                    read: Ok(unavailable),
                    ..calls.clone()
                }),
                &identity()
            ),
            Err(UkiPreflightError::FileUnavailable)
        );
    }
}
