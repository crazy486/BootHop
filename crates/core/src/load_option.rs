use crate::device_path::first_path_length;
use crate::{
    DevicePath, DevicePathInstance, DevicePathNode, DevicePathNodeKind, Error, FilePathNode,
    HardDriveNode, LoadOption, parse_device_path,
};

const MAX_LOAD_OPTION_BYTES: usize = 1_048_576;
const LOAD_OPTION_HEADER_BYTES: usize = 6;
const DEVICE_PATH_HEADER_BYTES: usize = 4;
const MEDIA_DEVICE_PATH: u8 = 0x04;
const HARD_DRIVE_SUBTYPE: u8 = 0x01;
const FILE_PATH_SUBTYPE: u8 = 0x04;
const END_DEVICE_PATH: u8 = 0x7f;
const END_ENTIRE_SUBTYPE: u8 = 0xff;
const END_NODE_LENGTH: u16 = 4;
const HARD_DRIVE_NODE_LENGTH: u16 = 42;
const ACTIVE_LOAD_OPTION: u32 = 1;
const ARCH_UKI_PATH: &str = "\\EFI\\BootHop\\arch.efi";
const ARCH_UKI_DESCRIPTION: &str = "BootHop Arch";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptEspIdentity {
    pub partition_number: u32,
    pub start_lba: u64,
    pub size_lba: u64,
    pub guid_uefi_bytes: [u8; 16],
}

/// Construct the one supported direct Arch entry from an already validated ESP identity.
pub fn arch_uki_load_option(esp: GptEspIdentity) -> Result<LoadOption, Error> {
    let hard_drive = HardDriveNode {
        partition_number: esp.partition_number,
        partition_start_lba: esp.start_lba,
        partition_size_lba: esp.size_lba,
        partition_signature_uefi_bytes: esp.guid_uefi_bytes,
        mbr_type: 2,
        signature_type: 2,
    };
    let hard_drive_payload = [
        hard_drive.partition_number.to_le_bytes().as_slice(),
        hard_drive.partition_start_lba.to_le_bytes().as_slice(),
        hard_drive.partition_size_lba.to_le_bytes().as_slice(),
        hard_drive.partition_signature_uefi_bytes.as_slice(),
        &[hard_drive.mbr_type, hard_drive.signature_type],
    ]
    .concat();

    let path_utf16 = ARCH_UKI_PATH.encode_utf16().collect::<Vec<_>>();
    let mut file_path_payload = Vec::new();
    let payload_bytes = path_utf16
        .len()
        .checked_add(1)
        .and_then(|units| units.checked_mul(2))
        .ok_or(Error::ResourceLimit)?;
    file_path_payload
        .try_reserve(payload_bytes)
        .map_err(|_| Error::ResourceLimit)?;
    for unit in &path_utf16 {
        file_path_payload.extend_from_slice(&unit.to_le_bytes());
    }
    file_path_payload.extend_from_slice(&0_u16.to_le_bytes());

    let file_node_length = DEVICE_PATH_HEADER_BYTES
        .checked_add(file_path_payload.len())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(Error::ResourceLimit)?;
    let file_path_list_length = usize::from(HARD_DRIVE_NODE_LENGTH)
        .checked_add(usize::from(file_node_length))
        .and_then(|length| length.checked_add(usize::from(END_NODE_LENGTH)))
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(Error::ResourceLimit)?;

    Ok(LoadOption {
        attributes: ACTIVE_LOAD_OPTION,
        description_utf16: ARCH_UKI_DESCRIPTION.encode_utf16().collect(),
        file_path_list_length,
        file_paths: vec![DevicePath {
            instances: vec![DevicePathInstance {
                nodes: vec![
                    DevicePathNode {
                        node_type: MEDIA_DEVICE_PATH,
                        subtype: HARD_DRIVE_SUBTYPE,
                        length: HARD_DRIVE_NODE_LENGTH,
                        payload: hard_drive_payload,
                        kind: DevicePathNodeKind::HardDrive(hard_drive),
                    },
                    DevicePathNode {
                        node_type: MEDIA_DEVICE_PATH,
                        subtype: FILE_PATH_SUBTYPE,
                        length: file_node_length,
                        payload: file_path_payload,
                        kind: DevicePathNodeKind::FilePath(FilePathNode { path_utf16 }),
                    },
                    DevicePathNode {
                        node_type: END_DEVICE_PATH,
                        subtype: END_ENTIRE_SUBTYPE,
                        length: END_NODE_LENGTH,
                        payload: Vec::new(),
                        kind: DevicePathNodeKind::EndEntire,
                    },
                ],
            }],
        }],
        optional_data: Vec::new(),
    })
}

/// Serialize the parsed UEFI load-option representation without accepting inconsistent nodes.
pub fn serialize_load_option(option: &LoadOption) -> Result<Vec<u8>, Error> {
    let mut file_path_bytes = Vec::new();
    for path in &option.file_paths {
        for instance in &path.instances {
            for node in &instance.nodes {
                let expected_length = DEVICE_PATH_HEADER_BYTES
                    .checked_add(node.payload.len())
                    .and_then(|length| u16::try_from(length).ok())
                    .ok_or(Error::MalformedDevicePath)?;
                if node.length != expected_length {
                    return Err(Error::MalformedDevicePath);
                }
                let additional = usize::from(node.length);
                let new_length = file_path_bytes
                    .len()
                    .checked_add(additional)
                    .ok_or(Error::ResourceLimit)?;
                if new_length > usize::from(u16::MAX) {
                    return Err(Error::ResourceLimit);
                }
                file_path_bytes
                    .try_reserve(additional)
                    .map_err(|_| Error::ResourceLimit)?;
                file_path_bytes.push(node.node_type);
                file_path_bytes.push(node.subtype);
                file_path_bytes.extend_from_slice(&node.length.to_le_bytes());
                file_path_bytes.extend_from_slice(&node.payload);
            }
        }
    }
    if file_path_bytes.len() != usize::from(option.file_path_list_length) {
        return Err(Error::MalformedLoadOption);
    }

    let description_bytes = option
        .description_utf16
        .len()
        .checked_add(1)
        .and_then(|units| units.checked_mul(2))
        .ok_or(Error::ResourceLimit)?;
    let total_length = LOAD_OPTION_HEADER_BYTES
        .checked_add(description_bytes)
        .and_then(|length| length.checked_add(file_path_bytes.len()))
        .and_then(|length| length.checked_add(option.optional_data.len()))
        .ok_or(Error::ResourceLimit)?;
    if total_length > MAX_LOAD_OPTION_BYTES {
        return Err(Error::ResourceLimit);
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve(total_length)
        .map_err(|_| Error::ResourceLimit)?;
    bytes.extend_from_slice(&option.attributes.to_le_bytes());
    bytes.extend_from_slice(&option.file_path_list_length.to_le_bytes());
    for unit in &option.description_utf16 {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&file_path_bytes);
    bytes.extend_from_slice(&option.optional_data);

    if parse_load_option(&bytes)? != *option {
        return Err(Error::MalformedLoadOption);
    }
    Ok(bytes)
}

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
