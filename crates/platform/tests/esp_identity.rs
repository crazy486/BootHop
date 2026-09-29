use boothop_platform::linux::esp_identity::{
    BlockNode, DeviceNumber, EspIdentityError, EspIdentitySource, LinuxEspIdentitySource,
    MountedEsp, ReadOnlyLinuxFs, discover_esp_identity, parse_guid_uefi_bytes,
};
use std::collections::BTreeMap;

const MOUNT: &str = "/boot";
const ESP: DeviceNumber = DeviceNumber {
    major: 259,
    minor: 1,
};
const DISK: DeviceNumber = DeviceNumber {
    major: 259,
    minor: 0,
};

struct Fixture {
    mounts: Vec<MountedEsp>,
    nodes: Vec<BlockNode>,
}

#[derive(Default)]
struct SyntheticLinuxFs {
    files: BTreeMap<String, String>,
    symlinks: BTreeMap<String, String>,
}

impl ReadOnlyLinuxFs for SyntheticLinuxFs {
    fn read_text(&self, path: &str) -> Result<String, String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| format!("missing synthetic file {path}"))
    }
    fn canonicalize(&self, path: &str) -> Result<String, String> {
        self.symlinks
            .get(path)
            .cloned()
            .ok_or_else(|| format!("missing synthetic symlink {path}"))
    }
}

impl EspIdentitySource for Fixture {
    fn mounted_esps(&self) -> Result<Vec<MountedEsp>, String> {
        Ok(self.mounts.clone())
    }
    fn block_nodes(
        &self,
        _mount_path: &str,
        _device: DeviceNumber,
    ) -> Result<Vec<BlockNode>, String> {
        Ok(self.nodes.clone())
    }
}

fn fixture() -> Fixture {
    Fixture {
        mounts: vec![MountedEsp {
            mount_path: MOUNT.into(),
            device: ESP,
            filesystem: "vfat".into(),
        }],
        nodes: vec![
            BlockNode {
                device: ESP,
                parent: Some(DISK),
                partition_number: Some(1),
                start_sectors_512: Some(2048),
                size_sectors_512: Some(1024 * 1024),
                logical_block_size: Some(512),
                partition_table: Some("gpt".into()),
                partition_guid: Some("00112233-4455-6677-8899-aabbccddeeff".into()),
            },
            BlockNode {
                device: DISK,
                parent: None,
                partition_number: None,
                start_sectors_512: None,
                size_sectors_512: None,
                logical_block_size: Some(512),
                partition_table: Some("gpt".into()),
                partition_guid: None,
            },
        ],
    }
}

#[test]
fn resolves_a_single_mounted_gpt_partition_into_uefi_hd_identity() {
    let identity = discover_esp_identity(&fixture(), MOUNT).unwrap();
    assert_eq!(identity.partition_number, 1);
    assert_eq!(identity.start_lba, 2048);
    assert_eq!(identity.size_lba, 1024 * 1024);
    assert_eq!(
        identity.partition_guid_uefi_bytes,
        [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff
        ]
    );
}

#[test]
fn converts_sysfs_512_sector_geometry_for_4kn_disk_and_checks_alignment() {
    let mut f = fixture();
    f.nodes[0].start_sectors_512 = Some(4096);
    f.nodes[0].size_sectors_512 = Some(8192);
    f.nodes[0].logical_block_size = Some(4096);
    f.nodes[1].logical_block_size = Some(4096);
    let identity = discover_esp_identity(&f, MOUNT).unwrap();
    assert_eq!((identity.start_lba, identity.size_lba), (512, 1024));
    f.nodes[0].start_sectors_512 = Some(4097);
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::InvalidField(_))
    ));
}

#[test]
fn refuses_missing_ambiguous_non_gpt_and_malformed_topology() {
    let f = fixture();
    assert!(matches!(
        discover_esp_identity(&f, "/efi"),
        Err(EspIdentityError::MissingMount(_))
    ));
    assert!(matches!(
        discover_esp_identity(&f, "/boot/../efi"),
        Err(EspIdentityError::InvalidField(_))
    ));
    let mut f = fixture();
    f.mounts.push(f.mounts[0].clone());
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::AmbiguousMount(_))
    ));
    let mut f = fixture();
    f.nodes[0].partition_table = Some("dos".into());
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::UnsupportedTopology(_))
    ));
    let mut f = fixture();
    f.nodes[0].partition_guid = None;
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::InvalidField(_))
    ));
    let mut f = fixture();
    f.nodes.push(f.nodes[0].clone());
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::AmbiguousBlockDevice(_))
    ));
    let mut f = fixture();
    f.nodes.push(f.nodes[1].clone());
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::AmbiguousBlockDevice(_))
    ));
}

#[test]
fn rejects_non_vfat_missing_fields_overflow_and_invalid_guid() {
    let mut f = fixture();
    f.mounts[0].filesystem = "ext4".into();
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::UnsupportedFilesystem(_))
    ));
    let mut f = fixture();
    f.nodes[0].partition_number = None;
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::InvalidField(_))
    ));
    let mut f = fixture();
    f.nodes[0].start_sectors_512 = Some(u64::MAX);
    f.nodes[0].logical_block_size = Some(4096);
    f.nodes[1].logical_block_size = Some(4096);
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::InvalidField(_))
    ));
    let mut f = fixture();
    f.nodes[0].start_sectors_512 = Some(0);
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::InvalidField(_))
    ));
    let mut f = fixture();
    f.nodes[0].partition_guid = Some("00000000-0000-0000-0000-000000000000".into());
    assert!(matches!(
        discover_esp_identity(&f, MOUNT),
        Err(EspIdentityError::InvalidField(_))
    ));
    assert!(matches!(
        parse_guid_uefi_bytes("broken"),
        Err(EspIdentityError::InvalidField(_))
    ));
    assert!(matches!(
        discover_esp_identity(&fixture(), "/"),
        Err(EspIdentityError::InvalidField(_))
    ));
    assert!(matches!(
        discover_esp_identity(&fixture(), "/boot/"),
        Err(EspIdentityError::InvalidField(_))
    ));
    assert!(matches!(
        discover_esp_identity(&fixture(), "/boot//efi"),
        Err(EspIdentityError::InvalidField(_))
    ));
}

#[test]
fn linux_read_only_source_parses_mountinfo_and_synthetic_sysfs_udev() {
    let mut fs = SyntheticLinuxFs::default();
    fs.files.insert(
        "/proc/self/mountinfo".into(),
        "24 1 0:47 / /run rw,relatime - tmpfs tmpfs rw\n36 25 259:1 / /boot\\040esp rw,relatime - vfat /dev/nvme0n1p1 rw\n".into(),
    );
    fs.symlinks.insert(
        "/sys/dev/block/259:1".into(),
        "/sys/devices/pci/block/nvme0n1/nvme0n1p1".into(),
    );
    fs.files.insert(
        "/sys/devices/pci/block/nvme0n1/nvme0n1p1/partition".into(),
        "1\n".into(),
    );
    fs.files.insert(
        "/sys/devices/pci/block/nvme0n1/nvme0n1p1/start".into(),
        "2048\n".into(),
    );
    fs.files.insert(
        "/sys/devices/pci/block/nvme0n1/nvme0n1p1/size".into(),
        "1048576\n".into(),
    );
    fs.files.insert(
        "/run/udev/data/b259:1".into(),
        "E:ID_PART_ENTRY_UUID=00112233-4455-6677-8899-aabbccddeeff\n".into(),
    );
    fs.files.insert(
        "/sys/devices/pci/block/nvme0n1/uevent".into(),
        "MAJOR=259\nMINOR=0\n".into(),
    );
    fs.files.insert(
        "/run/udev/data/b259:0".into(),
        "E:ID_PART_TABLE_TYPE=gpt\n".into(),
    );
    fs.files.insert(
        "/sys/devices/pci/block/nvme0n1/queue/logical_block_size".into(),
        "512\n".into(),
    );
    let source = LinuxEspIdentitySource::new(fs);
    let identity = discover_esp_identity(&source, "/boot esp").unwrap();
    assert_eq!(
        (
            identity.partition_number,
            identity.start_lba,
            identity.size_lba
        ),
        (1, 2048, 1048576)
    );
}
