//! Read-only preflight for the fixed BootHop UKI target on an already
//! discoverable EFI volume. This module deliberately has no native volume
//! adapter and exposes no mount, drive-letter, or write operation.

use boothop_core::{CanonicalDevicePathNode, CanonicalIdentity};

/// The only file this checker will request from a matched EFI volume.
pub const UKI_PATH_UTF16: &[u16] = &[
    b'\\' as u16,
    b'E' as u16,
    b'F' as u16,
    b'I' as u16,
    b'\\' as u16,
    b'B' as u16,
    b'o' as u16,
    b'o' as u16,
    b't' as u16,
    b'H' as u16,
    b'o' as u16,
    b'p' as u16,
    b'\\' as u16,
    b'a' as u16,
    b'r' as u16,
    b'c' as u16,
    b'h' as u16,
    b'.' as u16,
    b'e' as u16,
    b'f' as u16,
    b'i' as u16,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptPartition {
    pub number: u32,
    pub starting_lba: u64,
    pub size_lba: u64,
    /// GPT partition GUID in the UEFI device-path byte ordering.
    pub partition_guid_uefi_bytes: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EfiVolume {
    /// Opaque identifier meaningful only to the injected read-only provider.
    pub id: u64,
    pub partition: GptPartition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeEnumerationError {
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileReadError {
    Missing,
    Unsupported,
    Failed,
}

/// Read-only access to volumes already exposed as EFI volumes.
///
/// Both operations borrow immutably; this boundary intentionally has no
/// mount, drive-letter, or filesystem mutation capability.
pub trait ReadOnlyEfiVolumes {
    fn existing_efi_volumes(&self) -> Result<Vec<EfiVolume>, VolumeEnumerationError>;

    fn read_file(&self, volume_id: u64, path_utf16: &[u16]) -> Result<Vec<u8>, FileReadError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UkiPreflightError {
    UnsupportedIdentity,
    VolumeEnumerationFailed,
    NoMatchingVolume,
    AmbiguousVolumes,
    FileUnavailable,
    MalformedPe,
    MalformedUki,
}

/// Confirm that `identity` names exactly the fixed BootHop path on exactly
/// one existing GPT EFI volume and that its contents form a UKI PE image.
pub fn preflight_uki<V: ReadOnlyEfiVolumes + ?Sized>(
    volumes: &V,
    identity: &CanonicalIdentity,
) -> Result<(), UkiPreflightError> {
    let partition = target_partition(identity)?;
    let existing = volumes
        .existing_efi_volumes()
        .map_err(|_| UkiPreflightError::VolumeEnumerationFailed)?;
    let mut matches = existing
        .into_iter()
        .filter(|volume| volume.partition == partition);
    let volume = matches.next().ok_or(UkiPreflightError::NoMatchingVolume)?;
    if matches.next().is_some() {
        return Err(UkiPreflightError::AmbiguousVolumes);
    }

    let image = volumes
        .read_file(volume.id, UKI_PATH_UTF16)
        .map_err(|_| UkiPreflightError::FileUnavailable)?;
    validate_uki(&image)
}

fn target_partition(identity: &CanonicalIdentity) -> Result<GptPartition, UkiPreflightError> {
    let [
        CanonicalDevicePathNode::HardDrive(disk),
        CanonicalDevicePathNode::FilePath(path),
        CanonicalDevicePathNode::EndEntire(end),
    ] = &identity.nodes
    else {
        return Err(UkiPreflightError::UnsupportedIdentity);
    };

    let file_length = path
        .path_utf16
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_mul(2))
        .and_then(|length| length.checked_add(4))
        .and_then(|length| u16::try_from(length).ok());
    let expected_list_length = file_length
        .and_then(|length| 42_u16.checked_add(length))
        .and_then(|length| length.checked_add(4));

    if disk.node_type != 4
        || disk.subtype != 1
        || disk.length != 42
        || disk.mbr_type != 2
        || disk.signature_type != 2
        || disk.partition_number == 0
        || disk.partition_start_lba == 0
        || disk.partition_size_lba == 0
        || path.node_type != 4
        || path.subtype != 4
        || path.length != file_length.unwrap_or(0)
        || path.path_utf16 != UKI_PATH_UTF16
        || path.terminator != 0
        || end.node_type != 0x7f
        || end.subtype != 0xff
        || end.length != 4
        || expected_list_length != Some(identity.file_path_list_length)
    {
        return Err(UkiPreflightError::UnsupportedIdentity);
    }

    Ok(GptPartition {
        number: disk.partition_number,
        starting_lba: disk.partition_start_lba,
        size_lba: disk.partition_size_lba,
        partition_guid_uefi_bytes: disk.partition_signature_uefi_bytes,
    })
}

fn validate_uki(image: &[u8]) -> Result<(), UkiPreflightError> {
    let sections = pe_sections(image)?;
    for required in [b".linux".as_slice(), b".osrel", b".cmdline", b".initrd"] {
        let mut found = sections.iter().filter(|section| section.name == required);
        let section = found.next().ok_or(UkiPreflightError::MalformedUki)?;
        if found.next().is_some() || section.raw_size == 0 {
            return Err(UkiPreflightError::MalformedUki);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct PeSection<'a> {
    name: &'a [u8],
    raw_size: usize,
}

fn pe_sections(image: &[u8]) -> Result<Vec<PeSection<'_>>, UkiPreflightError> {
    let malformed = || UkiPreflightError::MalformedPe;
    if image.get(0..2) != Some(b"MZ") || image.len() < 0x40 {
        return Err(malformed());
    }
    let pe_offset = read_u32(image, 0x3c).ok_or_else(malformed)? as usize;
    let coff = pe_offset.checked_add(4).ok_or_else(malformed)?;
    if image.get(pe_offset..coff) != Some(b"PE\0\0") {
        return Err(malformed());
    }
    let section_count = read_u16(image, coff + 2).ok_or_else(malformed)? as usize;
    let machine = read_u16(image, coff).ok_or_else(malformed)?;
    let optional_size = read_u16(image, coff + 16).ok_or_else(malformed)? as usize;
    let optional = coff.checked_add(20).ok_or_else(malformed)?;
    let optional_end = optional.checked_add(optional_size).ok_or_else(malformed)?;
    let magic = read_u16(image, optional).ok_or_else(malformed)?;
    let minimum_optional_size = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return Err(malformed()),
    };
    if machine == 0
        || section_count == 0
        || section_count > 96
        || optional_size < minimum_optional_size
        || optional_end > image.len()
    {
        return Err(malformed());
    }
    let table_size = section_count.checked_mul(40).ok_or_else(malformed)?;
    let table_end = optional_end.checked_add(table_size).ok_or_else(malformed)?;
    if table_end > image.len() {
        return Err(malformed());
    }

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let header = optional_end + index * 40;
        let name_field = image.get(header..header + 8).ok_or_else(malformed)?;
        let name_end = name_field.iter().position(|byte| *byte == 0).unwrap_or(8);
        if !name_field[..name_end].is_ascii()
            || name_field[name_end..].iter().any(|byte| *byte != 0)
        {
            return Err(malformed());
        }
        let raw_size = read_u32(image, header + 16).ok_or_else(malformed)? as usize;
        let raw_offset = read_u32(image, header + 20).ok_or_else(malformed)? as usize;
        let raw_end = raw_offset.checked_add(raw_size).ok_or_else(malformed)?;
        if raw_size != 0 && raw_end > image.len() {
            return Err(malformed());
        }
        sections.push(PeSection {
            name: &name_field[..name_end],
            raw_size,
        });
    }
    Ok(sections)
}

fn read_u16(image: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        image.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(image: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        image.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
