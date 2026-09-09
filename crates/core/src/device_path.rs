use crate::{
    DevicePath, DevicePathInstance, DevicePathNode, DevicePathNodeKind, Error, FilePathNode,
    HardDriveNode,
};

const MAX_INPUT_BYTES: usize = 1_048_576;
const NODE_HEADER_BYTES: usize = 4;
const MEDIA_DEVICE_PATH: u8 = 0x04;
const HARD_DRIVE_SUBTYPE: u8 = 0x01;
const FILE_PATH_SUBTYPE: u8 = 0x04;
const END_DEVICE_PATH: u8 = 0x7f;
const END_INSTANCE_SUBTYPE: u8 = 0x01;
const END_ENTIRE_SUBTYPE: u8 = 0xff;
const END_NODE_LENGTH: u16 = 4;
const HARD_DRIVE_NODE_LENGTH: u16 = 42;

pub fn parse_device_path(bytes: &[u8]) -> Result<DevicePath, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::ResourceLimit);
    }

    let mut instances = Vec::new();
    let mut nodes = Vec::new();
    let mut offset = 0_usize;

    while offset < bytes.len() {
        let header_end = offset
            .checked_add(NODE_HEADER_BYTES)
            .ok_or(Error::MalformedDevicePath)?;
        let header = bytes
            .get(offset..header_end)
            .ok_or(Error::MalformedDevicePath)?;
        let node_type = *header.first().ok_or(Error::MalformedDevicePath)?;
        let subtype = *header.get(1).ok_or(Error::MalformedDevicePath)?;
        let length = read_u16(header, 2)?;
        let length_usize = usize::from(length);
        if length_usize < NODE_HEADER_BYTES {
            return Err(Error::MalformedDevicePath);
        }

        let node_end = offset
            .checked_add(length_usize)
            .ok_or(Error::MalformedDevicePath)?;
        let node_bytes = bytes
            .get(offset..node_end)
            .ok_or(Error::MalformedDevicePath)?;
        let payload = node_bytes
            .get(NODE_HEADER_BYTES..)
            .ok_or(Error::MalformedDevicePath)?;
        let kind = parse_node_kind(node_type, subtype, length, payload)?;
        let ends_instance = matches!(&kind, DevicePathNodeKind::EndInstance);
        let ends_entire = matches!(&kind, DevicePathNodeKind::EndEntire);

        nodes.push(DevicePathNode {
            node_type,
            subtype,
            length,
            payload: payload.to_vec(),
            kind,
        });
        offset = node_end;

        if ends_instance {
            if offset == bytes.len() {
                return Err(Error::MalformedDevicePath);
            }
            instances.push(DevicePathInstance {
                nodes: std::mem::take(&mut nodes),
            });
        } else if ends_entire {
            if offset != bytes.len() {
                return Err(Error::MalformedDevicePath);
            }
            instances.push(DevicePathInstance { nodes });
            return Ok(DevicePath { instances });
        }
    }

    Err(Error::MalformedDevicePath)
}

pub(crate) fn first_path_length(bytes: &[u8]) -> Result<usize, Error> {
    let mut offset = 0_usize;
    loop {
        let header_end = offset
            .checked_add(NODE_HEADER_BYTES)
            .ok_or(Error::MalformedDevicePath)?;
        let header = bytes
            .get(offset..header_end)
            .ok_or(Error::MalformedDevicePath)?;
        let node_type = *header.first().ok_or(Error::MalformedDevicePath)?;
        let subtype = *header.get(1).ok_or(Error::MalformedDevicePath)?;
        let length = read_u16(header, 2)?;
        let length_usize = usize::from(length);
        if length_usize < NODE_HEADER_BYTES {
            return Err(Error::MalformedDevicePath);
        }
        let node_end = offset
            .checked_add(length_usize)
            .ok_or(Error::MalformedDevicePath)?;
        bytes
            .get(offset..node_end)
            .ok_or(Error::MalformedDevicePath)?;

        if node_type == END_DEVICE_PATH {
            if length != END_NODE_LENGTH {
                return Err(Error::MalformedDevicePath);
            }
            match subtype {
                END_INSTANCE_SUBTYPE => {}
                END_ENTIRE_SUBTYPE => return Ok(node_end),
                _ => return Err(Error::MalformedDevicePath),
            }
        }
        offset = node_end;
    }
}

fn parse_node_kind(
    node_type: u8,
    subtype: u8,
    length: u16,
    payload: &[u8],
) -> Result<DevicePathNodeKind, Error> {
    match (node_type, subtype) {
        (END_DEVICE_PATH, END_INSTANCE_SUBTYPE) if length == END_NODE_LENGTH => {
            Ok(DevicePathNodeKind::EndInstance)
        }
        (END_DEVICE_PATH, END_ENTIRE_SUBTYPE) if length == END_NODE_LENGTH => {
            Ok(DevicePathNodeKind::EndEntire)
        }
        (END_DEVICE_PATH, _) => Err(Error::MalformedDevicePath),
        (MEDIA_DEVICE_PATH, HARD_DRIVE_SUBTYPE) => {
            parse_hard_drive(length, payload).map(DevicePathNodeKind::HardDrive)
        }
        (MEDIA_DEVICE_PATH, FILE_PATH_SUBTYPE) => {
            parse_file_path(payload).map(DevicePathNodeKind::FilePath)
        }
        _ => Ok(DevicePathNodeKind::Unknown),
    }
}

fn parse_hard_drive(length: u16, payload: &[u8]) -> Result<HardDriveNode, Error> {
    if length != HARD_DRIVE_NODE_LENGTH {
        return Err(Error::MalformedDevicePath);
    }
    let signature: [u8; 16] = payload
        .get(20..36)
        .ok_or(Error::MalformedDevicePath)?
        .try_into()
        .map_err(|_| Error::MalformedDevicePath)?;

    Ok(HardDriveNode {
        partition_number: read_u32(payload, 0)?,
        partition_start_lba: read_u64(payload, 4)?,
        partition_size_lba: read_u64(payload, 12)?,
        partition_signature_uefi_bytes: signature,
        mbr_type: *payload.get(36).ok_or(Error::MalformedDevicePath)?,
        signature_type: *payload.get(37).ok_or(Error::MalformedDevicePath)?,
    })
}

fn parse_file_path(payload: &[u8]) -> Result<FilePathNode, Error> {
    if payload.len() < 2 || !payload.len().is_multiple_of(2) {
        return Err(Error::MalformedDevicePath);
    }

    let (pairs, remainder) = payload.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(Error::MalformedDevicePath);
    }
    let code_units = pairs
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    if code_units.last() != Some(&0) {
        return Err(Error::MalformedDevicePath);
    }
    let path_length = code_units
        .len()
        .checked_sub(1)
        .ok_or(Error::MalformedDevicePath)?;
    let path = code_units
        .get(..path_length)
        .ok_or(Error::MalformedDevicePath)?;
    if path.contains(&0) || !valid_utf16(path) {
        return Err(Error::MalformedDevicePath);
    }

    Ok(FilePathNode {
        path_utf16: path.to_vec(),
    })
}

fn valid_utf16(code_units: &[u16]) -> bool {
    char::decode_utf16(code_units.iter().copied()).all(|decoded| decoded.is_ok())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let end = offset.checked_add(2).ok_or(Error::MalformedDevicePath)?;
    let pair: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(Error::MalformedDevicePath)?
        .try_into()
        .map_err(|_| Error::MalformedDevicePath)?;
    Ok(u16::from_le_bytes(pair))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::MalformedDevicePath)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(Error::MalformedDevicePath)?
        .try_into()
        .map_err(|_| Error::MalformedDevicePath)?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let end = offset.checked_add(8).ok_or(Error::MalformedDevicePath)?;
    let value: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(Error::MalformedDevicePath)?
        .try_into()
        .map_err(|_| Error::MalformedDevicePath)?;
    Ok(u64::from_le_bytes(value))
}
