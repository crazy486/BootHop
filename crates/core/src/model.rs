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
