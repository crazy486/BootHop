use crate::device_path::first_path_length;
use crate::{
    CanonicalDevicePathNode, CanonicalHardDriveNode, CanonicalIdentity, DevicePath,
    DevicePathInstance, DevicePathNode, DevicePathNodeKind, Error, FilePathNode, HardDriveNode,
    LoadOption, parse_device_path,
};

const MAX_LOAD_OPTION_BYTES: usize = 1_048_576;
const LOAD_OPTION_HEADER_BYTES: usize = 6;

pub fn parse_load_option(bytes: &[u8]) -> Result<LoadOption, Error> {
    if bytes.len() > MAX_LOAD_OPTION_BYTES {
        return Err(Error::ResourceLimit);
    }

    let header = bytes
        .get(..LOAD_OPTION_HEADER_BYTES)
        .ok_or(Error::MalformedLoadOption)?;
    let attributes = read_u32(header, 0)?;
    let file_path_list_length = read_u16(header, 4)?;

    let mut description_utf16 = Vec::new();
    let mut offset = LOAD_OPTION_HEADER_BYTES;
    loop {
        let unit_end = offset.checked_add(2).ok_or(Error::MalformedLoadOption)?;
        let unit = read_u16(bytes, offset)?;
        offset = unit_end;
        if unit == 0 {
            break;
        }
        description_utf16.push(unit);
    }
    if !valid_utf16(&description_utf16) {
        return Err(Error::MalformedLoadOption);
    }

    let file_path_end = offset
        .checked_add(usize::from(file_path_list_length))
        .ok_or(Error::MalformedLoadOption)?;
    let file_path_bytes = bytes
        .get(offset..file_path_end)
        .ok_or(Error::MalformedLoadOption)?;
    let optional_data = bytes
        .get(file_path_end..)
        .ok_or(Error::MalformedLoadOption)?
        .to_vec();

    let mut file_paths = Vec::new();
    let mut path_offset = 0_usize;
    while path_offset < file_path_bytes.len() {
        let remaining = file_path_bytes
            .get(path_offset..)
            .ok_or(Error::MalformedDevicePath)?;
        let path_length = first_path_length(remaining)?;
        let path_end = path_offset
            .checked_add(path_length)
            .ok_or(Error::MalformedDevicePath)?;
        let path_bytes = file_path_bytes
            .get(path_offset..path_end)
            .ok_or(Error::MalformedDevicePath)?;
        file_paths.push(parse_device_path(path_bytes)?);
        path_offset = path_end;
    }

    Ok(LoadOption {
        attributes,
        description_utf16,
        file_path_list_length,
        file_paths,
        optional_data,
    })
}

/// Serialize an EFI_LOAD_OPTION from parsed device paths. All wire lengths are derived here;
/// callers cannot provide a stale `file_path_list_length` that disagrees with the nodes.
pub fn serialize_load_option(option: &LoadOption) -> Result<Vec<u8>, Error> {
    if option.description_utf16.contains(&0) || !valid_utf16(&option.description_utf16) {
        return Err(Error::MalformedLoadOption);
    }
    let description_bytes = option
        .description_utf16
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(2))
        .ok_or(Error::ResourceLimit)?;
    let mut path_bytes = Vec::new();
    if option.file_paths.is_empty() {
        return Err(Error::MalformedDevicePath);
    }
    for path in &option.file_paths {
        serialize_device_path(path, &mut path_bytes)?;
    }
    let path_length = u16::try_from(path_bytes.len()).map_err(|_| Error::ResourceLimit)?;
    let total = LOAD_OPTION_HEADER_BYTES
        .checked_add(description_bytes)
        .and_then(|n| n.checked_add(path_bytes.len()))
        .and_then(|n| n.checked_add(option.optional_data.len()))
        .ok_or(Error::ResourceLimit)?;
    if total > MAX_LOAD_OPTION_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| Error::ResourceLimit)?;
    bytes.extend_from_slice(&option.attributes.to_le_bytes());
    bytes.extend_from_slice(&path_length.to_le_bytes());
    for unit in &option.description_utf16 {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&path_bytes);
    bytes.extend_from_slice(&option.optional_data);
    Ok(bytes)
}

/// Construct the fixed BootHop Arch load option from a GPT ESP identity.
pub fn arch_uki_load_option(
    partition_number: u32,
    partition_start_lba: u64,
    partition_size_lba: u64,
    partition_guid_uefi_bytes: [u8; 16],
) -> Result<LoadOption, Error> {
    if partition_number == 0
        || partition_start_lba == 0
        || partition_size_lba == 0
        || partition_guid_uefi_bytes == [0; 16]
    {
        return Err(Error::UnsupportedIdentityComponent);
    }
    let hd = HardDriveNode {
        partition_number,
        partition_start_lba,
        partition_size_lba,
        partition_signature_uefi_bytes: partition_guid_uefi_bytes,
        mbr_type: 2,
        signature_type: 2,
    };
    let path = DevicePath {
        instances: vec![DevicePathInstance {
            nodes: vec![
                DevicePathNode {
                    node_type: 4,
                    subtype: 1,
                    length: 42,
                    payload: hard_drive_payload(&hd),
                    kind: DevicePathNodeKind::HardDrive(hd),
                },
                file_path_node("\\EFI\\BootHop\\arch.efi")?,
                end_entire_node(),
            ],
        }],
    };
    let option = LoadOption {
        attributes: 1,
        description_utf16: "BootHop Arch UKI".encode_utf16().collect(),
        file_path_list_length: 0,
        file_paths: vec![path],
        optional_data: Vec::new(),
    };
    let serialized = serialize_load_option(&option)?;
    let parsed = parse_load_option(&serialized)?;
    Ok(parsed)
}

/// Construct the fixed BootHop load option from an already journaled canonical identity.
pub fn arch_uki_load_option_from_identity(
    identity: &CanonicalIdentity,
) -> Result<LoadOption, Error> {
    if identity.nodes.len() != 3 {
        return Err(Error::UnsupportedIdentityComponent);
    }
    let nodes = identity
        .nodes
        .iter()
        .map(|node| match node {
            CanonicalDevicePathNode::HardDrive(hd) => Ok(DevicePathNode {
                // Arch UKI entries are always GPT hard-drive paths. Refuse canonical identities
                // produced from MBR/unknown signatures rather than carrying them into provision.
                // The outer match remains total so malformed identities fail closed below.
                node_type: hd.node_type,
                subtype: hd.subtype,
                length: hd.length,
                payload: canonical_hd_payload(hd),
                kind: DevicePathNodeKind::HardDrive(HardDriveNode {
                    partition_number: hd.partition_number,
                    partition_start_lba: hd.partition_start_lba,
                    partition_size_lba: hd.partition_size_lba,
                    partition_signature_uefi_bytes: hd.partition_signature_uefi_bytes,
                    mbr_type: hd.mbr_type,
                    signature_type: hd.signature_type,
                }),
            }),
            CanonicalDevicePathNode::FilePath(file) => {
                if file.path_utf16
                    != "\\EFI\\BootHop\\arch.efi"
                        .encode_utf16()
                        .collect::<Vec<_>>()
                    || file.terminator != 0
                {
                    return Err(Error::UnsupportedIdentityComponent);
                }
                Ok(DevicePathNode {
                    node_type: file.node_type,
                    subtype: file.subtype,
                    length: file.length,
                    payload: file_payload(&file.path_utf16),
                    kind: DevicePathNodeKind::FilePath(FilePathNode {
                        path_utf16: file.path_utf16.clone(),
                    }),
                })
            }
            CanonicalDevicePathNode::EndEntire(end) => Ok(DevicePathNode {
                node_type: end.node_type,
                subtype: end.subtype,
                length: end.length,
                payload: Vec::new(),
                kind: DevicePathNodeKind::EndEntire,
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !matches!(
        nodes.as_slice(),
        [
            DevicePathNode {
                kind: DevicePathNodeKind::HardDrive(_),
                ..
            },
            DevicePathNode {
                kind: DevicePathNodeKind::FilePath(_),
                ..
            },
            DevicePathNode {
                kind: DevicePathNodeKind::EndEntire,
                ..
            }
        ]
    ) {
        return Err(Error::UnsupportedIdentityComponent);
    }
    let Some(DevicePathNode {
        length: 42,
        kind: DevicePathNodeKind::HardDrive(hd),
        ..
    }) = nodes.first()
    else {
        return Err(Error::UnsupportedIdentityComponent);
    };
    if hd.partition_number == 0
        || hd.partition_start_lba == 0
        || hd.partition_size_lba == 0
        || hd.partition_signature_uefi_bytes == [0; 16]
        || hd.mbr_type != 2
        || hd.signature_type != 2
    {
        return Err(Error::UnsupportedIdentityComponent);
    }
    let Some(DevicePathNode {
        node_type: 0x7f,
        subtype: 0xff,
        length: 4,
        ..
    }) = nodes.last()
    else {
        return Err(Error::UnsupportedIdentityComponent);
    };
    let option = LoadOption {
        attributes: 1,
        description_utf16: "BootHop Arch UKI".encode_utf16().collect(),
        file_path_list_length: 0,
        file_paths: vec![DevicePath {
            instances: vec![DevicePathInstance { nodes }],
        }],
        optional_data: Vec::new(),
    };
    let bytes = serialize_load_option(&option)?;
    parse_load_option(&bytes)
}

fn serialize_device_path(path: &DevicePath, output: &mut Vec<u8>) -> Result<(), Error> {
    if path.instances.len() != 1 {
        return Err(Error::MalformedDevicePath);
    }
    let instance = path.instances.first().ok_or(Error::MalformedDevicePath)?;
    if !matches!(
        instance.nodes.as_slice(),
        [
            DevicePathNode {
                kind: DevicePathNodeKind::HardDrive(_),
                ..
            },
            DevicePathNode {
                kind: DevicePathNodeKind::FilePath(_),
                ..
            },
            DevicePathNode {
                kind: DevicePathNodeKind::EndEntire,
                ..
            }
        ]
    ) {
        return Err(Error::MalformedDevicePath);
    }
    for node in &instance.nodes {
        match &node.kind {
            DevicePathNodeKind::HardDrive(hd) => {
                if node.node_type != 4
                    || node.subtype != 1
                    || node.length != 42
                    || hd.partition_number == 0
                    || hd.partition_start_lba == 0
                    || hd.partition_size_lba == 0
                    || hd.partition_signature_uefi_bytes == [0; 16]
                    || hd.mbr_type != 2
                    || hd.signature_type != 2
                    || node.payload != hard_drive_payload(hd)
                {
                    return Err(Error::MalformedDevicePath);
                }
                output.push(node.node_type);
                output.push(node.subtype);
                output.extend_from_slice(&node.length.to_le_bytes());
                output.extend_from_slice(&hard_drive_payload(hd));
            }
            DevicePathNodeKind::FilePath(file) => {
                if node.node_type != 4
                    || node.subtype != 4
                    || file.path_utf16.contains(&0)
                    || !valid_utf16(&file.path_utf16)
                {
                    return Err(Error::MalformedDevicePath);
                }
                let payload = file_payload(&file.path_utf16);
                let length = payload.len().checked_add(4).ok_or(Error::ResourceLimit)?;
                let length = u16::try_from(length).map_err(|_| Error::ResourceLimit)?;
                if node.length != length || node.payload != payload {
                    return Err(Error::MalformedDevicePath);
                }
                output.push(node.node_type);
                output.push(node.subtype);
                output.extend_from_slice(&length.to_le_bytes());
                output.extend_from_slice(&payload);
            }
            DevicePathNodeKind::EndEntire => {
                if node.node_type != 0x7f
                    || node.subtype != 0xff
                    || node.length != 4
                    || !node.payload.is_empty()
                {
                    return Err(Error::MalformedDevicePath);
                }
                output.extend_from_slice(&[0x7f, 0xff, 4, 0]);
            }
            DevicePathNodeKind::EndInstance | DevicePathNodeKind::Unknown => {
                return Err(Error::MalformedDevicePath);
            }
        }
    }
    Ok(())
}

fn hard_drive_payload(hd: &HardDriveNode) -> Vec<u8> {
    let mut payload = Vec::with_capacity(38);
    payload.extend_from_slice(&hd.partition_number.to_le_bytes());
    payload.extend_from_slice(&hd.partition_start_lba.to_le_bytes());
    payload.extend_from_slice(&hd.partition_size_lba.to_le_bytes());
    payload.extend_from_slice(&hd.partition_signature_uefi_bytes);
    payload.push(hd.mbr_type);
    payload.push(hd.signature_type);
    payload
}

fn canonical_hd_payload(hd: &CanonicalHardDriveNode) -> Vec<u8> {
    hard_drive_payload(&HardDriveNode {
        partition_number: hd.partition_number,
        partition_start_lba: hd.partition_start_lba,
        partition_size_lba: hd.partition_size_lba,
        partition_signature_uefi_bytes: hd.partition_signature_uefi_bytes,
        mbr_type: hd.mbr_type,
        signature_type: hd.signature_type,
    })
}

fn file_payload(path: &[u16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity((path.len() + 1) * 2);
    for unit in path.iter().chain(std::iter::once(&0)) {
        payload.extend_from_slice(&unit.to_le_bytes());
    }
    payload
}

fn file_path_node(path: &str) -> Result<DevicePathNode, Error> {
    let units = path.encode_utf16().collect::<Vec<_>>();
    let payload = file_payload(&units);
    let length = u16::try_from(payload.len() + 4).map_err(|_| Error::ResourceLimit)?;
    Ok(DevicePathNode {
        node_type: 4,
        subtype: 4,
        length,
        payload,
        kind: DevicePathNodeKind::FilePath(FilePathNode { path_utf16: units }),
    })
}

fn end_entire_node() -> DevicePathNode {
    DevicePathNode {
        node_type: 0x7f,
        subtype: 0xff,
        length: 4,
        payload: Vec::new(),
        kind: DevicePathNodeKind::EndEntire,
    }
}

fn valid_utf16(code_units: &[u16]) -> bool {
    char::decode_utf16(code_units.iter().copied()).all(|decoded| decoded.is_ok())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let end = offset.checked_add(2).ok_or(Error::MalformedLoadOption)?;
    let pair: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(Error::MalformedLoadOption)?
        .try_into()
        .map_err(|_| Error::MalformedLoadOption)?;
    Ok(u16::from_le_bytes(pair))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::MalformedLoadOption)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(Error::MalformedLoadOption)?
        .try_into()
        .map_err(|_| Error::MalformedLoadOption)?;
    Ok(u32::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_arch_option_serializes_exact_gpt_hd_file_path_and_computed_lengths() {
        let option = arch_uki_load_option(
            7,
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        )
        .unwrap();
        let bytes = serialize_load_option(&option).unwrap();
        let path_length = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(path_length, (42 + 48 + 4) as u16);
        assert_eq!(&bytes[..4], &1u32.to_le_bytes());
        let mut description = "BootHop Arch UKI"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        description.extend_from_slice(&[0, 0]);
        assert_eq!(&bytes[6..6 + description.len()], &description);
        let path_start = 6 + ("BootHop Arch UKI".encode_utf16().count() + 1) * 2;
        let hd = &bytes[path_start..path_start + 42];
        assert_eq!(u32::from_le_bytes(hd[4..8].try_into().unwrap()), 7);
        assert_eq!(
            u64::from_le_bytes(hd[8..16].try_into().unwrap()),
            0x0102_0304_0506_0708
        );
        assert_eq!(
            u64::from_le_bytes(hd[16..24].try_into().unwrap()),
            0x1112_1314_1516_1718
        );
        assert_eq!(
            &hd[24..40],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(&hd[40..], &[2, 2]);
        let parsed = parse_load_option(&bytes).unwrap();
        assert_eq!(parsed, option);
        assert_eq!(serialize_load_option(&parsed).unwrap(), bytes);
    }

    #[test]
    fn serializer_computes_path_length_and_preserves_optional_data() {
        let mut option = arch_uki_load_option(1, 9, 99, [0x5a; 16]).unwrap();
        option.file_path_list_length = u16::MAX;
        option.optional_data = vec![0, 0xff, 7];
        let bytes = serialize_load_option(&option).unwrap();
        let parsed = parse_load_option(&bytes).unwrap();
        assert_eq!(parsed.file_path_list_length, 42 + 48 + 4);
        assert_eq!(parsed.optional_data, [0, 0xff, 7]);
    }

    #[test]
    fn serializer_rejects_malformed_utf16_and_device_paths() {
        let mut option = arch_uki_load_option(1, 9, 99, [0x5a; 16]).unwrap();
        option.description_utf16 = vec![0xd800];
        assert_eq!(
            serialize_load_option(&option),
            Err(Error::MalformedLoadOption)
        );
        option = arch_uki_load_option(1, 9, 99, [0x5a; 16]).unwrap();
        option.file_paths[0].instances[0].nodes.pop();
        assert_eq!(
            serialize_load_option(&option),
            Err(Error::MalformedDevicePath)
        );
        option = arch_uki_load_option(1, 9, 99, [0x5a; 16]).unwrap();
        option.file_paths[0].instances[0].nodes.swap(0, 1);
        assert_eq!(
            serialize_load_option(&option),
            Err(Error::MalformedDevicePath)
        );
        option = arch_uki_load_option(1, 9, 99, [0x5a; 16]).unwrap();
        option.optional_data.resize(MAX_LOAD_OPTION_BYTES, 0);
        assert_eq!(serialize_load_option(&option), Err(Error::ResourceLimit));
        assert_eq!(
            arch_uki_load_option(0, 9, 99, [0; 16]),
            Err(Error::UnsupportedIdentityComponent)
        );
        assert_eq!(
            arch_uki_load_option(1, 0, 99, [1; 16]),
            Err(Error::UnsupportedIdentityComponent)
        );
        assert_eq!(
            arch_uki_load_option(1, 9, 99, [0; 16]),
            Err(Error::UnsupportedIdentityComponent)
        );
    }
}
