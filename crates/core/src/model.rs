#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BootId(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Os {
    Windows,
    Linux,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadOption {
    pub attributes: u32,
    pub description_utf16: Vec<u16>,
    pub file_path_list_length: u16,
    pub file_paths: Vec<DevicePath>,
    pub optional_data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevicePath {
    pub instances: Vec<DevicePathInstance>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevicePathInstance {
    pub nodes: Vec<DevicePathNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevicePathNode {
    pub node_type: u8,
    pub subtype: u8,
    pub length: u16,
    pub payload: Vec<u8>,
    pub kind: DevicePathNodeKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DevicePathNodeKind {
    HardDrive(HardDriveNode),
    FilePath(FilePathNode),
    EndInstance,
    EndEntire,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardDriveNode {
    pub partition_number: u32,
    pub partition_start_lba: u64,
    pub partition_size_lba: u64,
    pub partition_signature_uefi_bytes: [u8; 16],
    pub mbr_type: u8,
    pub signature_type: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePathNode {
    pub path_utf16: Vec<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Classification {
    NeedsConfirmation,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetRecord {
    pub os: Os,
    pub boot_id: BootId,
    pub identity: CanonicalIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalIdentity {
    pub file_path_list_length: u16,
    pub nodes: [CanonicalDevicePathNode; 3],
    pub optional_data: OpaqueExactV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalDevicePathNode {
    HardDrive(CanonicalHardDriveNode),
    FilePath(CanonicalFilePathNode),
    EndEntire(CanonicalEndEntireNode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalHardDriveNode {
    pub node_type: u8,
    pub subtype: u8,
    pub length: u16,
    pub partition_number: u32,
    pub partition_start_lba: u64,
    pub partition_size_lba: u64,
    pub partition_signature_uefi_bytes: [u8; 16],
    pub mbr_type: u8,
    pub signature_type: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalFilePathNode {
    pub node_type: u8,
    pub subtype: u8,
    pub length: u16,
    pub path_utf16: Vec<u16>,
    pub terminator: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalEndEntireNode {
    pub node_type: u8,
    pub subtype: u8,
    pub length: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpaqueAlgorithm {
    Sha256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpaqueExactV1 {
    pub algorithm: OpaqueAlgorithm,
    pub byte_length: u64,
    pub digest: [u8; 32],
}
