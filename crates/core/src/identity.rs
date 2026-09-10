use sha2::{Digest, Sha256};

use crate::{
    CanonicalDevicePathNode, CanonicalEndEntireNode, CanonicalFilePathNode, CanonicalHardDriveNode,
    CanonicalIdentity, Classification, DevicePathNode, DevicePathNodeKind, Error, FilePathNode,
    HardDriveNode, LoadOption, OpaqueAlgorithm, OpaqueExactV1, TargetRecord,
};

pub(crate) const MAX_LOAD_OPTION_BYTES: usize = 1_048_576;
const ACTIVE: u32 = 0x0000_0001;
const ACTIVE_HIDDEN: u32 = 0x0000_0009;

pub fn canonicalize(option: &LoadOption) -> Result<CanonicalIdentity, Error> {
    validate_outer(option)?;

    let path = option.file_paths.first().ok_or(Error::UnsupportedFormat)?;
    let instance = path.instances.first().ok_or(Error::UnsupportedFormat)?;
    let [hard_drive_node, file_path_node, end_node] = instance.nodes.as_slice() else {
        return Err(Error::UnsupportedFormat);
    };

    let hard_drive = canonical_hard_drive(hard_drive_node)?;
    let file_path = canonical_file_path(file_path_node)?;
    let end = canonical_end(end_node)?;

    let derived_path_list_length = hard_drive
        .length
        .checked_add(file_path.length)
        .and_then(|length| length.checked_add(end.length))
        .ok_or(Error::UnsupportedFormat)?;
    if derived_path_list_length != option.file_path_list_length {
        return Err(Error::UnsupportedFormat);
    }

    let digest: [u8; 32] = Sha256::digest(&option.optional_data).into();
    let byte_length =
        u64::try_from(option.optional_data.len()).map_err(|_| Error::ResourceLimit)?;

    let identity = CanonicalIdentity {
        file_path_list_length: option.file_path_list_length,
        nodes: [
            CanonicalDevicePathNode::HardDrive(hard_drive),
            CanonicalDevicePathNode::FilePath(file_path),
            CanonicalDevicePathNode::EndEntire(end),
        ],
        optional_data: OpaqueExactV1 {
            algorithm: OpaqueAlgorithm::Sha256,
            byte_length,
            digest,
        },
    };
    validate_canonical_identity(&identity)?;
    Ok(identity)
}

pub(crate) fn validate_canonical_identity(identity: &CanonicalIdentity) -> Result<(), Error> {
    let [
        CanonicalDevicePathNode::HardDrive(hard_drive),
        CanonicalDevicePathNode::FilePath(file_path),
        CanonicalDevicePathNode::EndEntire(end),
    ] = &identity.nodes
    else {
        return Err(Error::UnsupportedFormat);
    };

    if hard_drive.node_type != 4 || hard_drive.subtype != 1 || hard_drive.length != 42 {
        return Err(Error::UnsupportedFormat);
    }
    validate_hard_drive(&HardDriveNode {
        partition_number: hard_drive.partition_number,
        partition_start_lba: hard_drive.partition_start_lba,
        partition_size_lba: hard_drive.partition_size_lba,
        partition_signature_uefi_bytes: hard_drive.partition_signature_uefi_bytes,
        mbr_type: hard_drive.mbr_type,
        signature_type: hard_drive.signature_type,
    })?;

    let expected_file_length = file_path
        .path_utf16
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_mul(2))
        .and_then(|length| length.checked_add(4))
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(Error::UnsupportedFormat)?;
    if file_path.node_type != 4
        || file_path.subtype != 4
        || file_path.length != expected_file_length
        || file_path.terminator != 0
        || !valid_file_path(&FilePathNode {
            path_utf16: file_path.path_utf16.clone(),
        })
    {
        return Err(Error::UnsupportedFormat);
    }

    if end.node_type != 0x7f || end.subtype != 0xff || end.length != 4 {
        return Err(Error::UnsupportedFormat);
    }
    let derived_path_list_length = hard_drive
        .length
        .checked_add(file_path.length)
        .and_then(|length| length.checked_add(end.length))
        .ok_or(Error::UnsupportedFormat)?;
    if identity.file_path_list_length != derived_path_list_length
        || identity.optional_data.byte_length > MAX_LOAD_OPTION_BYTES as u64
        || (identity.optional_data.byte_length == 0
            && identity.optional_data.digest
                != [
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                    0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                    0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                ])
    {
        return Err(Error::UnsupportedFormat);
    }

    Ok(())
}

pub fn classify(option: &LoadOption) -> Classification {
    match canonicalize(option) {
        Ok(_) => Classification::NeedsConfirmation,
        Err(_) => Classification::Unsupported,
    }
}

pub fn validate_target(saved: &TargetRecord, current: &LoadOption) -> Result<(), Error> {
    if canonicalize(current)? != saved.identity {
        return Err(Error::IdentityMismatch);
    }
    Ok(())
}

fn validate_outer(option: &LoadOption) -> Result<(), Error> {
    if !matches!(option.attributes, ACTIVE | ACTIVE_HIDDEN)
        || option.description_utf16.contains(&0)
        || !valid_utf16(&option.description_utf16)
        || option.file_paths.len() != 1
        || option.file_paths[0].instances.len() != 1
    {
        return Err(Error::UnsupportedFormat);
    }

    let description_bytes = option
        .description_utf16
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(2))
        .ok_or(Error::ResourceLimit)?;
    let encoded_length = 6_usize
        .checked_add(description_bytes)
        .and_then(|length| length.checked_add(usize::from(option.file_path_list_length)))
        .and_then(|length| length.checked_add(option.optional_data.len()))
        .ok_or(Error::ResourceLimit)?;
    if encoded_length > MAX_LOAD_OPTION_BYTES {
        return Err(Error::ResourceLimit);
    }

    Ok(())
}

fn canonical_hard_drive(node: &DevicePathNode) -> Result<CanonicalHardDriveNode, Error> {
    let DevicePathNodeKind::HardDrive(hard_drive) = &node.kind else {
        return Err(Error::UnsupportedFormat);
    };
    if node.node_type != 4 || node.subtype != 1 || node.length != 42 {
        return Err(Error::UnsupportedFormat);
    }
    validate_hard_drive(hard_drive)?;

    let mut expected_payload = hard_drive.partition_number.to_le_bytes().to_vec();
    expected_payload.extend_from_slice(&hard_drive.partition_start_lba.to_le_bytes());
    expected_payload.extend_from_slice(&hard_drive.partition_size_lba.to_le_bytes());
    expected_payload.extend_from_slice(&hard_drive.partition_signature_uefi_bytes);
    expected_payload.extend_from_slice(&[hard_drive.mbr_type, hard_drive.signature_type]);
    if node.payload != expected_payload {
        return Err(Error::UnsupportedFormat);
    }

    Ok(CanonicalHardDriveNode {
        node_type: node.node_type,
        subtype: node.subtype,
        length: node.length,
        partition_number: hard_drive.partition_number,
        partition_start_lba: hard_drive.partition_start_lba,
        partition_size_lba: hard_drive.partition_size_lba,
        partition_signature_uefi_bytes: hard_drive.partition_signature_uefi_bytes,
        mbr_type: hard_drive.mbr_type,
        signature_type: hard_drive.signature_type,
    })
}

fn validate_hard_drive(hard_drive: &HardDriveNode) -> Result<(), Error> {
    if hard_drive.partition_number == 0
        || hard_drive.partition_size_lba == 0
        || hard_drive.partition_signature_uefi_bytes == [0; 16]
        || hard_drive.mbr_type != 2
        || hard_drive.signature_type != 2
        || hard_drive
            .partition_start_lba
            .checked_add(hard_drive.partition_size_lba)
            .is_none()
    {
        return Err(Error::UnsupportedFormat);
    }
    Ok(())
}

fn canonical_file_path(node: &DevicePathNode) -> Result<CanonicalFilePathNode, Error> {
    let DevicePathNodeKind::FilePath(file_path) = &node.kind else {
        return Err(Error::UnsupportedFormat);
    };
    let expected_length = file_path
        .path_utf16
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_mul(2))
        .and_then(|length| length.checked_add(4))
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(Error::UnsupportedFormat)?;
    if node.node_type != 4
        || node.subtype != 4
        || node.length != expected_length
        || !valid_file_path(file_path)
    {
        return Err(Error::UnsupportedFormat);
    }

    let mut expected_payload = Vec::with_capacity(usize::from(expected_length) - 4);
    for code_unit in &file_path.path_utf16 {
        expected_payload.extend_from_slice(&code_unit.to_le_bytes());
    }
    expected_payload.extend_from_slice(&0_u16.to_le_bytes());
    if node.payload != expected_payload {
        return Err(Error::UnsupportedFormat);
    }

    Ok(CanonicalFilePathNode {
        node_type: node.node_type,
        subtype: node.subtype,
        length: node.length,
        path_utf16: file_path.path_utf16.clone(),
        terminator: 0,
    })
}

fn valid_file_path(file_path: &FilePathNode) -> bool {
    let path = &file_path.path_utf16;
    if path.first() != Some(&(b'\\' as u16))
        || path.len() <= 1
        || path.contains(&(b'/' as u16))
        || path.contains(&0)
        || !valid_utf16(path)
    {
        return false;
    }

    path[1..]
        .split(|unit| *unit == b'\\' as u16)
        .all(|part| !part.is_empty() && part != [b'.' as u16] && part != [b'.' as u16, b'.' as u16])
}

fn canonical_end(node: &DevicePathNode) -> Result<CanonicalEndEntireNode, Error> {
    if node.node_type != 0x7f
        || node.subtype != 0xff
        || node.length != 4
        || !node.payload.is_empty()
        || node.kind != DevicePathNodeKind::EndEntire
    {
        return Err(Error::UnsupportedFormat);
    }
    Ok(CanonicalEndEntireNode {
        node_type: node.node_type,
        subtype: node.subtype,
        length: node.length,
    })
}

fn valid_utf16(code_units: &[u16]) -> bool {
    char::decode_utf16(code_units.iter().copied()).all(|decoded| decoded.is_ok())
}
