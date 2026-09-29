use std::fmt;

/// Partition identity encoded in a UEFI HD() node. GPT GUID bytes use UEFI mixed-endian wire order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EspPartitionIdentity {
    pub partition_number: u32,
    pub start_lba: u64,
    pub size_lba: u64,
    pub partition_guid_uefi_bytes: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountedEsp {
    pub mount_path: String,
    pub device: DeviceNumber,
    pub filesystem: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceNumber {
    pub major: u32,
    pub minor: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockNode {
    pub device: DeviceNumber,
    pub parent: Option<DeviceNumber>,
    pub partition_number: Option<u32>,
    /// Linux sysfs partition `start`/`size` units are always 512-byte sectors.
    pub start_sectors_512: Option<u64>,
    pub size_sectors_512: Option<u64>,
    /// Logical block size of the whole disk, in bytes, required for UEFI HD() LBA values.
    pub logical_block_size: Option<u32>,
    pub partition_table: Option<String>,
    pub partition_guid: Option<String>,
}

/// Read-only adapter boundary. Production implementations must source mountinfo and sysfs only;
/// the resolver itself is deterministic and does not perform I/O or execute commands.
pub trait EspIdentitySource {
    fn mounted_esps(&self) -> Result<Vec<MountedEsp>, String>;
    fn block_nodes(&self, mount_path: &str, device: DeviceNumber)
    -> Result<Vec<BlockNode>, String>;
}

/// Minimal read-only Linux filesystem needed to resolve mountinfo and block topology. Tests can
/// provide synthetic files and directory entries without opening any host firmware paths.
pub trait ReadOnlyLinuxFs {
    fn read_text(&self, path: &str) -> Result<String, String>;
    fn canonicalize(&self, path: &str) -> Result<String, String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemReadOnlyLinuxFs;

impl ReadOnlyLinuxFs for SystemReadOnlyLinuxFs {
    fn read_text(&self, path: &str) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))
    }

    fn canonicalize(&self, path: &str) -> Result<String, String> {
        std::fs::canonicalize(path)
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|error| format!("cannot resolve {path}: {error}"))
    }
}

pub struct LinuxEspIdentitySource<F: ReadOnlyLinuxFs> {
    fs: F,
}

impl<F: ReadOnlyLinuxFs> LinuxEspIdentitySource<F> {
    pub fn new(fs: F) -> Self {
        Self { fs }
    }
}

impl LinuxEspIdentitySource<SystemReadOnlyLinuxFs> {
    /// Production source is read-only and reads `/proc/self/mountinfo`, `/sys`, and udev metadata.
    pub fn system() -> Self {
        Self::new(SystemReadOnlyLinuxFs)
    }
}

impl<F: ReadOnlyLinuxFs> EspIdentitySource for LinuxEspIdentitySource<F> {
    fn mounted_esps(&self) -> Result<Vec<MountedEsp>, String> {
        let mountinfo = self.fs.read_text("/proc/self/mountinfo")?;
        parse_mountinfo(&mountinfo)
    }

    fn block_nodes(
        &self,
        mount_path: &str,
        device: DeviceNumber,
    ) -> Result<Vec<BlockNode>, String> {
        let current = self.mounted_esps()?;
        let matches = current
            .iter()
            .filter(|mount| mount.mount_path == mount_path)
            .collect::<Vec<_>>();
        if matches.len() != 1
            || !matches.iter().any(|mount| {
                mount.device == device && mount.filesystem.eq_ignore_ascii_case("vfat")
            })
        {
            return Err("selected ESP mount changed or became ambiguous during discovery".into());
        }
        let mut result = Vec::new();
        let sys_dev = format!("/sys/dev/block/{}:{}", device.major, device.minor);
        let resolved = self.fs.canonicalize(&sys_dev)?;
        let partition_file = format!("{resolved}/partition");
        let partition = match self.fs.read_text(&partition_file) {
            Ok(value) => Some(parse_u32_sysfs(&partition_file, value.trim())?),
            Err(_) => None,
        };
        if let Some(number) = partition {
            let parent_path = resolved
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .ok_or_else(|| "invalid resolved sysfs partition path".to_string())?;
            let start_path = format!("{resolved}/start");
            let size_path = format!("{resolved}/size");
            let start = parse_u64_sysfs(&start_path, self.fs.read_text(&start_path)?.trim())?;
            let size = parse_u64_sysfs(&size_path, self.fs.read_text(&size_path)?.trim())?;
            let partuuid = udev_property(&self.fs, device, "ID_PART_ENTRY_UUID")?;
            let parent_dev = find_parent_device(&self.fs, parent_path)?;
            let table = udev_property(&self.fs, parent_dev, "ID_PART_TABLE_TYPE")?;
            let block_size_path = format!("{parent_path}/queue/logical_block_size");
            let logical_block_size = parse_u32_sysfs(
                &block_size_path,
                self.fs.read_text(&block_size_path)?.trim(),
            )?;
            result.push(BlockNode {
                device,
                parent: Some(parent_dev),
                partition_number: Some(number),
                start_sectors_512: Some(start),
                size_sectors_512: Some(size),
                logical_block_size: Some(logical_block_size),
                partition_table: table.clone(),
                partition_guid: partuuid,
            });
            result.push(BlockNode {
                device: parent_dev,
                parent: None,
                partition_number: None,
                start_sectors_512: None,
                size_sectors_512: None,
                logical_block_size: Some(logical_block_size),
                partition_table: table,
                partition_guid: None,
            });
        } else {
            // Whole-disk mounts, device-mapper layers, mdraid, loop, and multipath layouts
            // are deliberately not guessed into a GPT partition HD() tuple.
            result.push(BlockNode {
                device,
                parent: None,
                partition_number: None,
                start_sectors_512: None,
                size_sectors_512: None,
                logical_block_size: None,
                partition_table: None,
                partition_guid: None,
            });
        }
        Ok(result)
    }
}

fn parse_mountinfo(text: &str) -> Result<Vec<MountedEsp>, String> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        let (pre, post) = line
            .split_once(" - ")
            .ok_or_else(|| "malformed /proc/self/mountinfo".to_string())?;
        let fields = pre.split_ascii_whitespace().collect::<Vec<_>>();
        let tail = post.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 || tail.len() < 2 {
            return Err("malformed /proc/self/mountinfo".into());
        }
        let device = parse_device_number(fields[2])?;
        let mount_path = decode_mount_field(fields[4])?;
        mounts.push(MountedEsp {
            mount_path,
            device,
            filesystem: tail[0].into(),
        });
    }
    Ok(mounts)
}

fn parse_device_number(text: &str) -> Result<DeviceNumber, String> {
    let (major, minor) = text
        .split_once(':')
        .ok_or_else(|| "invalid mountinfo device number".to_string())?;
    Ok(DeviceNumber {
        major: major
            .parse()
            .map_err(|_| "invalid mountinfo major number".to_string())?,
        minor: minor
            .parse()
            .map_err(|_| "invalid mountinfo minor number".to_string())?,
    })
}

fn decode_mount_field(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let octal = bytes
                .get(i + 1..i + 4)
                .ok_or_else(|| "invalid escaped mount path".to_string())?;
            if !octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                return Err("invalid escaped mount path".into());
            }
            let digit = |b: u8| u32::from(b - b'0');
            let decoded = (digit(octal[0]) << 6) | (digit(octal[1]) << 3) | digit(octal[2]);
            if decoded > 255 {
                return Err("invalid escaped mount path".into());
            }
            result.push(decoded as u8);
            i += 4;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result).map_err(|_| "mount path is not valid UTF-8".into())
}

fn parse_u32_sysfs(path: &str, value: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("invalid sysfs value in {path}"))
}
fn parse_u64_sysfs(path: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("invalid sysfs value in {path}"))
}

fn udev_property<F: ReadOnlyLinuxFs>(
    fs: &F,
    device: DeviceNumber,
    key: &str,
) -> Result<Option<String>, String> {
    let path = format!("/run/udev/data/b{}:{}", device.major, device.minor);
    let text = fs.read_text(&path)?;
    let prefix = format!("E:{key}=");
    let values = text
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some((*one).into())),
        _ => Err(format!(
            "ambiguous udev property {key} for {}:{}",
            device.major, device.minor
        )),
    }
}

fn find_parent_device<F: ReadOnlyLinuxFs>(
    fs: &F,
    parent_path: &str,
) -> Result<DeviceNumber, String> {
    let uevent = fs.read_text(&format!("{parent_path}/uevent"))?;
    let major = unique_uevent_value(&uevent, "MAJOR")?;
    let minor = unique_uevent_value(&uevent, "MINOR")?;
    Ok(DeviceNumber {
        major: major
            .parse()
            .map_err(|_| "invalid sysfs disk MAJOR".to_string())?,
        minor: minor
            .parse()
            .map_err(|_| "invalid sysfs disk MINOR".to_string())?,
    })
}

fn unique_uevent_value<'a>(uevent: &'a str, key: &str) -> Result<&'a str, String> {
    let prefix = format!("{key}=");
    let values = uevent
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(value),
        [] => Err(format!("sysfs disk lacks {key}")),
        _ => Err(format!("sysfs disk has duplicate {key}")),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EspIdentityError {
    Io(String),
    MissingMount(String),
    AmbiguousMount(String),
    UnsupportedFilesystem(String),
    MissingBlockDevice(DeviceNumber),
    AmbiguousBlockDevice(DeviceNumber),
    UnsupportedTopology(String),
    InvalidField(String),
    Overflow,
}

impl fmt::Display for EspIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(s) | Self::UnsupportedTopology(s) | Self::InvalidField(s) => f.write_str(s),
            Self::MissingMount(s) => write!(f, "no mounted ESP at {s}"),
            Self::AmbiguousMount(s) => write!(f, "multiple mounts claim ESP path {s}"),
            Self::UnsupportedFilesystem(s) => write!(f, "unsupported ESP filesystem {s}"),
            Self::MissingBlockDevice(dev) => {
                write!(f, "missing block device {}:{}", dev.major, dev.minor)
            }
            Self::AmbiguousBlockDevice(dev) => {
                write!(f, "ambiguous block device {}:{}", dev.major, dev.minor)
            }
            Self::Overflow => f.write_str("partition identity exceeds UEFI HD() limits"),
        }
    }
}

impl std::error::Error for EspIdentityError {}

pub fn discover_esp_identity(
    source: &impl EspIdentitySource,
    mount_path: &str,
) -> Result<EspPartitionIdentity, EspIdentityError> {
    validate_mount_path(mount_path)?;
    let mounts = source.mounted_esps().map_err(EspIdentityError::Io)?;
    let matches = mounts
        .iter()
        .filter(|mount| mount.mount_path == mount_path)
        .collect::<Vec<_>>();
    let mount = match matches.as_slice() {
        [] => return Err(EspIdentityError::MissingMount(mount_path.into())),
        [one] => *one,
        _ => return Err(EspIdentityError::AmbiguousMount(mount_path.into())),
    };
    if !mount.filesystem.eq_ignore_ascii_case("vfat") {
        return Err(EspIdentityError::UnsupportedFilesystem(
            mount.filesystem.clone(),
        ));
    }
    let nodes = source
        .block_nodes(mount_path, mount.device)
        .map_err(EspIdentityError::Io)?;
    resolve_partition(mount.device, &nodes)
}

fn resolve_partition(
    device: DeviceNumber,
    nodes: &[BlockNode],
) -> Result<EspPartitionIdentity, EspIdentityError> {
    let mut current = device;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        if !seen.insert(current) {
            return Err(EspIdentityError::UnsupportedTopology(
                "block-device parent cycle".into(),
            ));
        }
        let matches = nodes
            .iter()
            .filter(|node| node.device == current)
            .collect::<Vec<_>>();
        let node = match matches.as_slice() {
            [] => return Err(EspIdentityError::MissingBlockDevice(current)),
            [one] => *one,
            _ => return Err(EspIdentityError::AmbiguousBlockDevice(current)),
        };
        if node.partition_number.is_some()
            || node.start_sectors_512.is_some()
            || node.size_sectors_512.is_some()
            || node.partition_guid.is_some()
        {
            if node.partition_table.as_deref() != Some("gpt") {
                return Err(EspIdentityError::UnsupportedTopology(
                    "ESP partition is not proven to belong to a GPT disk".into(),
                ));
            }
            let partition_number = node.partition_number.ok_or_else(|| {
                EspIdentityError::InvalidField("missing GPT partition number".into())
            })?;
            let start_sectors_512 = node.start_sectors_512.ok_or_else(|| {
                EspIdentityError::InvalidField("missing GPT partition start sector".into())
            })?;
            let size_sectors_512 = node.size_sectors_512.ok_or_else(|| {
                EspIdentityError::InvalidField("missing GPT partition size".into())
            })?;
            let logical_block_size = node.logical_block_size.ok_or_else(|| {
                EspIdentityError::InvalidField("missing disk logical block size".into())
            })?;
            let partition_guid = node.partition_guid.as_deref().ok_or_else(|| {
                EspIdentityError::InvalidField("missing GPT partition GUID".into())
            })?;
            let parent_device = node.parent.ok_or_else(|| {
                EspIdentityError::UnsupportedTopology("GPT partition lacks a parent disk".into())
            })?;
            let parents = nodes
                .iter()
                .filter(|candidate| candidate.device == parent_device)
                .collect::<Vec<_>>();
            let disk = match parents.as_slice() {
                [disk] => *disk,
                [] => return Err(EspIdentityError::MissingBlockDevice(parent_device)),
                _ => return Err(EspIdentityError::AmbiguousBlockDevice(parent_device)),
            };
            if disk.partition_table.as_deref() != Some("gpt")
                || disk.partition_number.is_some()
                || disk.start_sectors_512.is_some()
                || disk.size_sectors_512.is_some()
                || disk.partition_guid.is_some()
                || disk.logical_block_size != Some(logical_block_size)
            {
                return Err(EspIdentityError::UnsupportedTopology(
                    "ESP partition parent is not one matching GPT disk".into(),
                ));
            }
            if partition_number == 0 || start_sectors_512 == 0 || size_sectors_512 == 0 {
                return Err(EspIdentityError::InvalidField(
                    "invalid GPT partition number, start, or size".into(),
                ));
            }
            if logical_block_size == 0 || !logical_block_size.is_multiple_of(512) {
                return Err(EspIdentityError::InvalidField(
                    "unsupported disk logical block size".into(),
                ));
            }
            let sectors_per_lba = u64::from(logical_block_size / 512);
            if !start_sectors_512.is_multiple_of(sectors_per_lba)
                || !size_sectors_512.is_multiple_of(sectors_per_lba)
            {
                return Err(EspIdentityError::InvalidField(
                    "partition geometry is not aligned to disk logical blocks".into(),
                ));
            }
            let partition_guid_uefi_bytes = parse_guid_uefi_bytes(partition_guid)?;
            if partition_guid_uefi_bytes == [0; 16] {
                return Err(EspIdentityError::InvalidField(
                    "GPT partition GUID cannot be zero".into(),
                ));
            }
            return Ok(EspPartitionIdentity {
                partition_number,
                start_lba: start_sectors_512 / sectors_per_lba,
                size_lba: size_sectors_512 / sectors_per_lba,
                partition_guid_uefi_bytes,
            });
        }
        if node.partition_table.is_some() {
            return Err(EspIdentityError::UnsupportedTopology(
                "disk node encountered before ESP partition".into(),
            ));
        }
        current = node.parent.ok_or_else(|| {
            EspIdentityError::UnsupportedTopology(
                "ESP mount device has no GPT partition ancestor".into(),
            )
        })?;
    }
}

fn validate_mount_path(path: &str) -> Result<(), EspIdentityError> {
    if !path.starts_with('/')
        || path == "/"
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('\0')
        || path
            .split('/')
            .skip(1)
            .any(|part| part == ".." || part == "." || part.is_empty())
    {
        return Err(EspIdentityError::InvalidField(
            "ESP mount path must be an absolute normalized non-root path".into(),
        ));
    }
    Ok(())
}

pub fn parse_guid_uefi_bytes(text: &str) -> Result<[u8; 16], EspIdentityError> {
    let parts = text.split('-').collect::<Vec<_>>();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return Err(EspIdentityError::InvalidField(
            "invalid GPT partition GUID".into(),
        ));
    }
    let a = u32::from_str_radix(parts[0], 16)
        .map_err(|_| EspIdentityError::InvalidField("invalid GPT partition GUID".into()))?;
    let b = u16::from_str_radix(parts[1], 16)
        .map_err(|_| EspIdentityError::InvalidField("invalid GPT partition GUID".into()))?;
    let c = u16::from_str_radix(parts[2], 16)
        .map_err(|_| EspIdentityError::InvalidField("invalid GPT partition GUID".into()))?;
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&a.to_le_bytes());
    bytes[4..6].copy_from_slice(&b.to_le_bytes());
    bytes[6..8].copy_from_slice(&c.to_le_bytes());
    for (index, pair) in parts[3]
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .chain(parts[4].as_bytes().as_chunks::<2>().0.iter())
        .enumerate()
    {
        let hex = std::str::from_utf8(pair)
            .map_err(|_| EspIdentityError::InvalidField("invalid GPT partition GUID".into()))?;
        bytes[8 + index] = u8::from_str_radix(hex, 16)
            .map_err(|_| EspIdentityError::InvalidField("invalid GPT partition GUID".into()))?;
    }
    Ok(bytes)
}
