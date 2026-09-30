//! Read-only preflight for the fixed BootHop UKI target on an already
//! discoverable EFI volume. This module has no native Windows volume calls
//! and exposes no mount, drive-letter, or write operation. The
//! `NativeEfiCalls` contract below is fake-testable only; actual Windows EFI
//! volume access remains unverified and production keeps its unavailable
//! provider until a native ESP fixture can validate it. Any future enumerator
//! must not treat `FindFirstVolume` alone as proof that hidden ESPs are covered.

use boothop_core::{CanonicalDevicePathNode, CanonicalIdentity};
use std::collections::BTreeSet;

/// Bound parser work and reject implausibly large UKI images before parsing.
pub const MAX_UKI_BYTES: usize = 128 * 1024 * 1024;

/// GPT on-disk byte ordering for the EFI System Partition type GUID.
pub const EFI_SYSTEM_PARTITION_TYPE_GUID_UEFI_BYTES: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

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
    TooLarge,
    Failed,
}

/// A candidate returned by a future native read-only volume enumerator.
/// Offsets and lengths are byte counts from the partition API; the adapter
/// converts them using the reported logical sector size before comparing the
/// saved UEFI hard-drive node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePartitionScheme {
    Gpt,
    Mbr,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeEfiVolume {
    pub id: u64,
    pub partition_scheme: NativePartitionScheme,
    pub partition_number: u32,
    pub starting_offset_bytes: u64,
    pub size_bytes: u64,
    pub logical_sector_size: u32,
    pub partition_guid_uefi_bytes: [u8; 16],
    pub partition_type_guid_uefi_bytes: [u8; 16],
}

/// Stable metadata observed on an already-open file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileHandleIdentity {
    /// `FILE_ID_INFO.VolumeSerialNumber`; part of the file identity pair.
    pub volume_serial_number: u64,
    /// `FILE_ID_INFO.FileId`.
    pub file_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentitySnapshot {
    /// `None` means the native API could not establish a stable file identity.
    pub identity: Option<FileHandleIdentity>,
    pub size: u64,
    pub is_regular_file: bool,
    pub is_reparse_point: bool,
}

/// Read-only result from one handle-bound read of the fixed UKI path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFixedUkiRead {
    /// Opaque volume identity actually used by the opened file handle.
    pub volume_id: u64,
    /// Partition identity observed for the volume handle used by the read.
    pub partition: GptPartition,
    pub before: FileIdentitySnapshot,
    pub after: FileIdentitySnapshot,
    pub bytes: Vec<u8>,
}

/// Narrow native call contract for a future Windows implementation.
///
/// This intentionally exposes no path argument and no mount, drive-letter,
/// create, replace, write, delete, label, or firmware operation. The native
/// implementation is not yet present or verified; tests use fake calls only.
pub trait NativeEfiCalls {
    fn enumerate_existing_efi_volumes(
        &self,
    ) -> Result<Vec<NativeEfiVolume>, VolumeEnumerationError>;

    /// Open the exact fixed UKI path read-only and return identity evidence
    /// captured before and after reading at most `max_bytes` from that handle.
    fn read_fixed_uki(
        &self,
        volume_id: u64,
        expected_partition: GptPartition,
        max_bytes: usize,
    ) -> Result<NativeFixedUkiRead, FileReadError>;
}

pub struct NativeEfiVolumeAdapter<C> {
    calls: C,
}

impl<C> NativeEfiVolumeAdapter<C> {
    pub fn new(calls: C) -> Self {
        Self { calls }
    }
}

impl<C: NativeEfiCalls> ReadOnlyEfiVolumes for NativeEfiVolumeAdapter<C> {
    fn existing_efi_volumes(&self) -> Result<Vec<EfiVolume>, VolumeEnumerationError> {
        self.calls.enumerate_existing_efi_volumes().map(|volumes| {
            volumes
                .into_iter()
                .filter_map(normalize_native_volume)
                .collect()
        })
    }

    fn read_fixed_uki(
        &self,
        volume_id: u64,
        expected_partition: GptPartition,
    ) -> Result<Vec<u8>, FileReadError> {
        // Re-enumerate immediately before opening, and bind the opaque ID to
        // exactly one current normalized partition identity. This catches a
        // stale/reused ID; the read result must also report that partition.
        let current = self
            .calls
            .enumerate_existing_efi_volumes()
            .map_err(|_| FileReadError::Failed)?;
        let mut seen_ids = BTreeSet::new();
        if current
            .iter()
            .any(|candidate| !seen_ids.insert(candidate.id))
        {
            return Err(FileReadError::Unsupported);
        }
        let current = current
            .into_iter()
            .filter_map(normalize_native_volume)
            .collect::<Vec<_>>();
        let mut matching_partitions = current
            .iter()
            .filter(|volume| volume.partition == expected_partition);
        let volume = matching_partitions
            .next()
            .ok_or(FileReadError::Unsupported)?;
        if matching_partitions.next().is_some() || volume.id != volume_id {
            return Err(FileReadError::Unsupported);
        }

        let read = self
            .calls
            .read_fixed_uki(volume_id, volume.partition, MAX_UKI_BYTES)?;
        if read.volume_id != volume_id || read.partition != volume.partition {
            return Err(FileReadError::Unsupported);
        }
        if read.before.size > MAX_UKI_BYTES as u64 || read.after.size > MAX_UKI_BYTES as u64 {
            return Err(FileReadError::TooLarge);
        }
        let Some(before_identity) = read.before.identity else {
            return Err(FileReadError::Unsupported);
        };
        let Some(after_identity) = read.after.identity else {
            return Err(FileReadError::Unsupported);
        };
        if !read.before.is_regular_file
            || !read.after.is_regular_file
            || read.before.is_reparse_point
            || read.after.is_reparse_point
            || before_identity.volume_serial_number == 0
            || before_identity.file_id == [0; 16]
            || after_identity.volume_serial_number == 0
            || after_identity.file_id == [0; 16]
            || read.before != read.after
            || read.bytes.len() as u64 != read.before.size
        {
            return Err(FileReadError::Unsupported);
        }
        Ok(read.bytes)
    }
}

fn normalize_native_volume(volume: NativeEfiVolume) -> Option<EfiVolume> {
    let sector_size = u64::from(volume.logical_sector_size);
    if volume.partition_scheme != NativePartitionScheme::Gpt
        || volume.partition_type_guid_uefi_bytes != EFI_SYSTEM_PARTITION_TYPE_GUID_UEFI_BYTES
        || !matches!(volume.logical_sector_size, 512 | 4096)
        || volume.partition_number == 0
        || volume.partition_guid_uefi_bytes == [0; 16]
        || volume.starting_offset_bytes == 0
        || volume.size_bytes == 0
        || !volume.starting_offset_bytes.is_multiple_of(sector_size)
        || !volume.size_bytes.is_multiple_of(sector_size)
    {
        return None;
    }
    let starting_lba = volume.starting_offset_bytes / sector_size;
    let size_lba = volume.size_bytes / sector_size;
    starting_lba.checked_add(size_lba)?;
    Some(EfiVolume {
        id: volume.id,
        partition: GptPartition {
            number: volume.partition_number,
            starting_lba,
            size_lba,
            partition_guid_uefi_bytes: volume.partition_guid_uefi_bytes,
        },
    })
}

/// Read-only access to volumes already exposed as EFI volumes.
///
/// Both operations borrow immutably; this boundary intentionally has no
/// mount, drive-letter, or filesystem mutation capability.
pub trait ReadOnlyEfiVolumes {
    fn existing_efi_volumes(&self) -> Result<Vec<EfiVolume>, VolumeEnumerationError>;

    fn read_fixed_uki(
        &self,
        volume_id: u64,
        expected_partition: GptPartition,
    ) -> Result<Vec<u8>, FileReadError>;
}

/// Whether a saved identity requests the one special path that needs local UKI preflight.
/// Other existing targets, including the user's GRUB entry, keep their current Switch flow.
pub fn uses_fixed_uki_path(identity: &CanonicalIdentity) -> bool {
    matches!(
        &identity.nodes[1],
        CanonicalDevicePathNode::FilePath(path) if path.path_utf16 == UKI_PATH_UTF16
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UkiPreflightError {
    UnsupportedIdentity,
    VolumeEnumerationFailed,
    NoMatchingVolume,
    AmbiguousVolumes,
    FileUnavailable,
    ImageTooLarge,
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
        .read_fixed_uki(volume.id, volume.partition)
        .map_err(|error| match error {
            FileReadError::TooLarge => UkiPreflightError::ImageTooLarge,
            FileReadError::Missing | FileReadError::Unsupported | FileReadError::Failed => {
                UkiPreflightError::FileUnavailable
            }
        })?;
    if image.len() > MAX_UKI_BYTES {
        return Err(UkiPreflightError::ImageTooLarge);
    }
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
        || disk
            .partition_start_lba
            .checked_add(disk.partition_size_lba)
            .is_none()
        || disk.partition_signature_uefi_bytes == [0; 16]
        || path.node_type != 4
        || path.subtype != 4
        || path.length != file_length.unwrap_or(0)
        || path.path_utf16 != UKI_PATH_UTF16
        || path.terminator != 0
        || end.node_type != 0x7f
        || end.subtype != 0xff
        || end.length != 4
        || expected_list_length != Some(identity.file_path_list_length)
        || identity.optional_data.byte_length != 0
        || identity.optional_data.digest != SHA256_EMPTY
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
    if pe_offset < 0x40 {
        return Err(malformed());
    }
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
    let minimum_optional_size = if magic == 0x20b {
        112
    } else {
        return Err(malformed());
    };
    if machine != 0x8664
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
        if raw_size != 0 && (raw_offset < table_end || raw_end > image.len()) {
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
