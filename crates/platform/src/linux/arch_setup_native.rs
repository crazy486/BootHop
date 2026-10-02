//! Native Arch setup calls. This module is intentionally not reachable from either helper main.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use boothop_core::{BootId, GptEspIdentity};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};

use super::{
    arch_identity::InstalledIdentity,
    arch_setup_system::{ArchSystemCalls, HostMetadata},
    arch_uki::EspInfo,
    store::LinuxStore,
};

const EFI_FS_MAGIC: u64 = 0xde5e81e4;
const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const ESP_TYPE: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Holds the BootHop operation lock and pacman's exclusive DB lock for the whole setup.
/// Construction is production-only and never used by the packaged setup executable.
pub struct NativeArchCalls {
    store: LinuxStore,
    pacman_lock: File,
    pacman_inode: u64,
}
impl NativeArchCalls {
    pub fn open() -> Result<Self, i32> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(1);
        }
        let store = LinuxStore::open().map_err(|_| 1)?;
        let lock_path = Path::new("/var/lib/pacman/db.lck");
        check_parent_chain(lock_path)?;
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lock_path)
            .map_err(code)?;
        let inode = lock.metadata().map_err(code)?.ino();
        Ok(Self {
            store,
            pacman_lock: lock,
            pacman_inode: inode,
        })
    }
}
impl Drop for NativeArchCalls {
    fn drop(&mut self) {
        let _ = self.pacman_lock.sync_all();
        let path = Path::new("/var/lib/pacman/db.lck");
        if let Ok(meta) = fs::symlink_metadata(path)
            && meta.is_file()
            && meta.ino() == self.pacman_inode
            && meta.uid() == 0
        {
            let _ = fs::remove_file(path);
        }
    }
}
fn code(error: std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(5)
}
fn check_parent_chain(path: &Path) -> Result<(), i32> {
    if !path.is_absolute() {
        return Err(22);
    }
    let root = fs::symlink_metadata("/").map_err(code)?;
    if !root.is_dir() || root.uid() != 0 || root.gid() != 0 || root.mode() & 0o022 != 0 {
        return Err(1);
    }
    let mut current = PathBuf::from("/");
    for component in path.parent().ok_or(22)?.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => current.push(part),
            _ => return Err(22),
        }
        let meta = fs::symlink_metadata(&current).map_err(code)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != 0
            || meta.gid() != 0
            || meta.mode() & 0o022 != 0
        {
            return Err(1);
        }
    }
    Ok(())
}
fn file_metadata(path: &Path) -> Result<Option<fs::Metadata>, i32> {
    check_parent_chain(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(40),
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(code(error)),
    }
}
fn meta_snapshot(meta: &fs::Metadata) -> HostMetadata {
    HostMetadata {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
        links: meta.nlink(),
        size: meta.size(),
    }
}
fn read_checked(path: &Path) -> Result<Option<Vec<u8>>, i32> {
    let Some(before) = file_metadata(path)? else {
        return Ok(None);
    };
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.size() > 512 * 1024 * 1024
    {
        return Err(1);
    }
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| error.raw_os_error())?;
    let file: File = fd.into();
    let mut bytes = Vec::new();
    (&file)
        .take(before.size() + 1)
        .read_to_end(&mut bytes)
        .map_err(code)?;
    let after = file_metadata(path)?.ok_or(5)?;
    if bytes.len() as u64 != before.size()
        || before.ino() != after.ino()
        || before.dev() != after.dev()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.mtime() != after.mtime()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.size() != after.size()
        || file.metadata().map_err(code)?.ino() != before.ino()
    {
        return Err(5);
    }
    Ok(Some(bytes))
}
fn temp_path(path: &Path) -> Result<PathBuf, i32> {
    let name = path.file_name().ok_or(22)?.to_str().ok_or(22)?;
    Ok(path.with_file_name(format!(
        ".{name}-{}-{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )))
}
fn sync_parent(path: &Path) -> Result<(), i32> {
    File::open(path.parent().ok_or(22)?)
        .map_err(code)?
        .sync_all()
        .map_err(code)
}
fn write_temp(path: &Path, bytes: &[u8], mode: u32) -> Result<PathBuf, i32> {
    check_parent_chain(path)?;
    let temp = temp_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&temp)
        .map_err(code)?;
    let result = (|| {
        file.write_all(bytes).map_err(code)?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(code)?;
        file.sync_all().map_err(code)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    Ok(temp)
}
fn command_output(program: &str, args: &[&str]) -> Result<String, i32> {
    trusted_executable(Path::new(program))?;
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .env("LC_ALL", "C")
        .output()
        .map_err(code)?;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err(5);
    }
    String::from_utf8(output.stdout).map_err(|_| 84)
}
fn trusted_executable(path: &Path) -> Result<(), i32> {
    let meta = file_metadata(path)?.ok_or(2)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o022 != 0
        || meta.mode() & 0o111 == 0
    {
        return Err(1);
    }
    Ok(())
}
fn pairs(text: &str) -> Result<std::collections::BTreeMap<String, String>, i32> {
    let mut values = std::collections::BTreeMap::new();
    for token in text.split_whitespace() {
        let (key, quoted) = token.split_once('=').ok_or(22)?;
        let value = quoted
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or(22)?;
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(22);
        }
    }
    Ok(values)
}
/// Parse one complete findmnt snapshot. A malformed row makes the entire observation unknown.
fn mount_candidates(snapshot: &str) -> Result<Vec<(String, String)>, i32> {
    let mut candidates = Vec::new();
    let mut rows = 0;
    let mut boot_seen = false;
    let mut efi_seen = false;
    for line in snapshot.lines() {
        if line.is_empty() {
            return Err(22);
        }
        rows += 1;
        let fields = pairs(line)?;
        let target = fields.get("TARGET").ok_or(22)?;
        let source = fields.get("SOURCE").ok_or(22)?;
        let filesystem = fields.get("FSTYPE").ok_or(22)?;
        if target == "/boot" || target == "/efi" {
            let seen = if target == "/boot" {
                &mut boot_seen
            } else {
                &mut efi_seen
            };
            if *seen {
                return Err(22);
            }
            *seen = true;
            if filesystem == "vfat" {
                candidates.push((target.clone(), source.clone()));
            }
        }
    }
    if rows == 0 {
        return Err(22);
    }
    Ok(candidates)
}
fn guid_bytes(value: &str) -> Result<[u8; 16], i32> {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != 5 || parts.iter().map(|p| p.len()).collect::<Vec<_>>() != [8, 4, 4, 4, 12] {
        return Err(22);
    }
    let first = u32::from_str_radix(parts[0], 16)
        .map_err(|_| 22)?
        .to_le_bytes();
    let second = u16::from_str_radix(parts[1], 16)
        .map_err(|_| 22)?
        .to_le_bytes();
    let third = u16::from_str_radix(parts[2], 16)
        .map_err(|_| 22)?
        .to_le_bytes();
    let tail = format!("{}{}", parts[3], parts[4]);
    let mut result = [0_u8; 16];
    result[..4].copy_from_slice(&first);
    result[4..6].copy_from_slice(&second);
    result[6..8].copy_from_slice(&third);
    for (index, pair) in tail.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[8 + index] =
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| 22)?, 16).map_err(|_| 22)?;
    }
    Ok(result)
}
fn efi_dir() -> Result<std::os::fd::OwnedFd, i32> {
    let mut dir = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.raw_os_error())?;
    for part in ["sys", "firmware", "efi", "efivars"] {
        dir = rustix::fs::openat(
            &dir,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|e| e.raw_os_error())?;
    }
    if rustix::fs::fstatfs(&dir)
        .map_err(|e| e.raw_os_error())?
        .f_type as u64
        != EFI_FS_MAGIC
    {
        return Err(19);
    }
    Ok(dir)
}
fn efi_name(name: &[u8]) -> Result<&str, i32> {
    let text = std::str::from_utf8(name).map_err(|_| 22)?;
    if !text.ends_with(GUID)
        || text.len() > 64
        || !(text.starts_with("Boot") || text.starts_with("SecureBoot"))
        || text
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-'))
    {
        return Err(22);
    }
    Ok(text)
}
fn efi_read_native(name: &[u8]) -> Result<Option<(u32, Vec<u8>)>, i32> {
    let name = efi_name(name)?;
    let dir = efi_dir()?;
    let fd = match rustix::fs::openat(
        &dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.raw_os_error()),
    };
    let before = rustix::fs::fstat(&fd).map_err(|e| e.raw_os_error())?;
    if before.st_mode & 0o170000 != 0o100000 || before.st_size < 4 || before.st_size > 1_048_580 {
        return Err(22);
    }
    let file: File = fd.into();
    let mut bytes = Vec::new();
    (&file)
        .take(before.st_size as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(code)?;
    let after = file.metadata().map_err(code)?;
    if bytes.len() as i64 != before.st_size
        || after.ino() != before.st_ino
        || after.size() != before.st_size as u64
    {
        return Err(5);
    }
    let attr = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| 22)?);
    Ok(Some((attr, bytes[4..].to_vec())))
}
fn efi_write_once(name: &str, data: &[u8], exclusive: bool) -> Result<(), i32> {
    let dir = efi_dir()?;
    efi_write_one_in_dir(&dir, name, data, exclusive)
}
fn efi_write_one_in_dir(
    dir: &std::os::fd::OwnedFd,
    name: &str,
    data: &[u8],
    exclusive: bool,
) -> Result<(), i32> {
    let flags = OFlags::WRONLY
        | OFlags::CLOEXEC
        | OFlags::NOFOLLOW
        | if exclusive {
            OFlags::CREATE | OFlags::EXCL
        } else {
            OFlags::empty()
        };
    let fd = rustix::fs::openat(dir, name, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|e| e.raw_os_error())?;
    let count = rustix::io::write(&fd, data).map_err(|e| e.raw_os_error())?;
    if count != data.len() {
        return Err(5);
    }
    Ok(())
}

impl ArchSystemCalls for NativeArchCalls {
    fn metadata(&self, path: &Path) -> Result<Option<HostMetadata>, i32> {
        Ok(file_metadata(path)?.as_ref().map(meta_snapshot))
    }
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, i32> {
        read_checked(path)
    }
    fn list(&self, path: &Path) -> Result<Vec<String>, i32> {
        check_parent_chain(&path.join(".entry"))?;
        let mut result = Vec::new();
        for entry in fs::read_dir(path).map_err(code)? {
            let entry = entry.map_err(code)?;
            result.push(entry.file_name().into_string().map_err(|_| 84)?);
            if result.len() > 65536 {
                return Err(27);
            }
        }
        Ok(result)
    }
    fn replace_if_exact(&mut self, path: &Path, old: &[u8], new: &[u8]) -> Result<(), i32> {
        if read_checked(path)?.as_deref() != Some(old) {
            return Err(16);
        }
        let mode = file_metadata(path)?.ok_or(2)?.mode() & 0o777;
        let temp = write_temp(path, new, mode)?;
        if read_checked(path)?.as_deref() != Some(old) {
            let _ = fs::remove_file(temp);
            return Err(16);
        }
        let outcome = fs::rename(&temp, path)
            .map_err(code)
            .and_then(|_| sync_parent(path));
        if outcome.is_err() {
            let _ = fs::remove_file(temp);
        }
        outcome
    }
    fn create_exclusive(&mut self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), i32> {
        if file_metadata(path)?.is_some() {
            return Err(17);
        }
        let temp = write_temp(path, bytes, mode)?;
        let outcome = fs::hard_link(&temp, path)
            .map_err(code)
            .and_then(|_| sync_parent(path));
        let _ = fs::remove_file(temp);
        outcome
    }
    fn ensure_directory(&mut self, path: &Path) -> Result<(), i32> {
        check_parent_chain(path)?;
        if file_metadata(path)?.is_none() {
            fs::create_dir(path).map_err(code)?;
            if file_metadata(path)?.ok_or(2)?.mode() & 0o777 != 0o755 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(code)?;
            }
            sync_parent(path)?;
        }
        let meta = file_metadata(path)?.ok_or(2)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o777 != 0o755 {
            return Err(1);
        }
        Ok(())
    }
    fn remove_regular(&mut self, path: &Path) -> Result<(), i32> {
        let meta = file_metadata(path)?.ok_or(2)?;
        if !meta.is_file() || meta.uid() != 0 || meta.nlink() != 1 {
            return Err(1);
        }
        fs::remove_file(path).map_err(code)?;
        sync_parent(path)
    }
    fn run(&mut self, command: &Path, args: &[&str], initial: bool) -> Result<(), i32> {
        if command != Path::new("/usr/bin/mkinitcpio")
            || args.len() != 2
            || args[0] != "-p"
            || !super::arch_uki::is_safe_flavor(args[1])
            || !initial
        {
            return Err(22);
        }
        trusted_executable(command)?;
        let status = Command::new(command)
            .args(args)
            .stdin(Stdio::null())
            .env_remove("BOOTHOP_TESTING")
            .env_remove("BOOTHOP_TEST_ROOT")
            .env("BOOTHOP_ARCH_INITIAL", "1")
            .status()
            .map_err(code)?;
        if !status.success() {
            return Err(5);
        }
        Ok(())
    }
    fn esp_info(&self) -> Result<EspInfo, i32> {
        let mut found = None;
        let snapshot = command_output(
            "/usr/bin/findmnt",
            &[
                "--noheadings",
                "--list",
                "--output",
                "TARGET,SOURCE,FSTYPE",
                "--pairs",
            ],
        )?;
        for (mount, source) in mount_candidates(&snapshot)? {
            if !source.starts_with("/dev/")
                || source[5..]
                    .bytes()
                    .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'-' | b'.'))
            {
                return Err(22);
            }
            let meta = fs::symlink_metadata(&source).map_err(code)?;
            if !meta.file_type().is_block_device() || meta.file_type().is_symlink() {
                return Err(22);
            }
            let columns = command_output(
                "/usr/bin/lsblk",
                &[
                    "--noheadings",
                    "--bytes",
                    "--pairs",
                    "--output",
                    "PARTN,START,SIZE,LOG-SEC,PARTTYPE,PARTUUID",
                    &source,
                ],
            )?;
            let fields = pairs(columns.trim())?;
            if fields
                .get("PARTTYPE")
                .is_none_or(|t| !t.eq_ignore_ascii_case(ESP_TYPE))
            {
                return Err(22);
            }
            let number = fields
                .get("PARTN")
                .ok_or(22)?
                .parse::<u32>()
                .map_err(|_| 22)?;
            let start_512 = fields
                .get("START")
                .ok_or(22)?
                .parse::<u64>()
                .map_err(|_| 22)?;
            let bytes = fields
                .get("SIZE")
                .ok_or(22)?
                .parse::<u64>()
                .map_err(|_| 22)?;
            let sector = fields
                .get("LOG-SEC")
                .ok_or(22)?
                .parse::<u64>()
                .map_err(|_| 22)?;
            if number == 0
                || !matches!(sector, 512 | 4096)
                || start_512.checked_mul(512).is_none_or(|n| n % sector != 0)
                || bytes == 0
                || bytes % sector != 0
            {
                return Err(22);
            }
            let identity = GptEspIdentity {
                partition_number: number,
                start_lba: start_512 * 512 / sector,
                size_lba: bytes / sector,
                guid_uefi_bytes: guid_bytes(fields.get("PARTUUID").ok_or(22)?)?,
            };
            if found.is_some() {
                return Err(22);
            }
            found = Some(EspInfo {
                mount_point: PathBuf::from(mount),
                filesystem: "vfat".into(),
                is_mounted: true,
                is_efi_system_partition: true,
                gpt_identity: Some(identity),
            });
        }
        found.ok_or(2)
    }
    fn attest_package_route(&self, hook: &[u8], script: &[u8]) -> Result<bool, i32> {
        const HOOK_DIGEST: [u8; 32] = [
            0x9f, 0xc6, 0x07, 0xe8, 0x1d, 0x2f, 0x09, 0xaa, 0x0d, 0xfd, 0x31, 0x38, 0x05, 0x27,
            0x7a, 0xf9, 0x29, 0x77, 0x53, 0x5b, 0xd2, 0x22, 0xf1, 0xe8, 0x6c, 0xaf, 0x5f, 0xbb,
            0x28, 0x13, 0x8c, 0xb4,
        ];
        const SCRIPT_DIGEST: [u8; 32] = [
            0x33, 0xe2, 0xaf, 0x3c, 0x50, 0xf0, 0xb9, 0xc7, 0x69, 0x63, 0xad, 0xfe, 0xc1, 0x5a,
            0x12, 0x46, 0xfb, 0x24, 0x9a, 0xb4, 0x65, 0x6f, 0xe4, 0xb9, 0xaf, 0x08, 0x09, 0xb0,
            0x72, 0xa4, 0x52, 0xc3,
        ];
        Ok(Sha256::digest(hook).as_slice() == HOOK_DIGEST
            && Sha256::digest(script).as_slice() == SCRIPT_DIGEST)
    }
    fn efi_names(&mut self) -> Result<Vec<Vec<u8>>, i32> {
        use std::ffi::CStr;
        let dir = efi_dir()?;
        let iterator = rustix::fs::Dir::read_from(&dir).map_err(|e| e.raw_os_error())?;
        let mut names = Vec::new();
        for entry in iterator {
            let entry = entry.map_err(|e| e.raw_os_error())?;
            let name: &CStr = entry.file_name();
            names.push(name.to_bytes().to_vec());
            if names.len() > 65536 {
                return Err(27);
            }
        }
        Ok(names)
    }
    fn efi_read(&self, name: &[u8]) -> Result<Option<(u32, Vec<u8>)>, i32> {
        efi_read_native(name)
    }
    fn efi_create(&mut self, id: BootId, option: &[u8]) -> Result<(), i32> {
        if id == BootId(0) || option.len() > 1_048_576 {
            return Err(22);
        }
        let mut bytes = 7_u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(option);
        efi_write_once(&format!("Boot{:04X}-{GUID}", id.0), &bytes, true)
    }
    fn efi_replace_order(&mut self, order: &[u8]) -> Result<(), i32> {
        if order.len() > 131072 || !order.len().is_multiple_of(2) {
            return Err(22);
        }
        if efi_read_native(format!("BootOrder-{GUID}").as_bytes())?.map(|(attr, _)| attr) != Some(7)
        {
            return Err(22);
        }
        let mut bytes = 7_u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(order);
        efi_write_once(&format!("BootOrder-{GUID}"), &bytes, false)
    }
    fn save_marker(&mut self, identity: &InstalledIdentity) -> Result<(), i32> {
        self.store
            .save_arch_identity(identity)
            .map_err(|error| match error {
                boothop_core::Error::PlatformIo { raw_code, .. }
                | boothop_core::Error::StoreDurabilityUnknown { raw_code } => raw_code,
                _ => 1,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn gpt_uuid_uses_uefi_field_byte_order_and_rejects_bad_shapes() {
        assert_eq!(
            guid_bytes("00112233-4455-6677-8899-aabbccddeeff"),
            Ok([
                0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ])
        );
        assert!(guid_bytes("00112233-4455-6677-8899").is_err());
        assert!(pairs("SOURCE=\"/dev/sda1\" FSTYPE=\"vfat\"").is_ok());
        assert!(pairs("SOURCE=\"/dev/sda1\" SOURCE=\"/dev/sdb1\"").is_err());
    }

    #[test]
    fn isolated_descriptor_write_is_exclusive_and_single_attempt() {
        let temp = std::env::temp_dir().join(format!(
            "boothop-arch-efi-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&temp).unwrap();
        let dir = rustix::fs::open(
            &temp,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let payload = [7_u32.to_le_bytes().as_slice(), b"synthetic"].concat();
        assert_eq!(
            efi_write_one_in_dir(&dir, "Boot0001-test", &payload, true),
            Ok(())
        );
        assert_eq!(
            efi_write_one_in_dir(&dir, "Boot0001-test", &payload, true),
            Err(17)
        );
        assert_eq!(fs::read(temp.join("Boot0001-test")).unwrap(), payload);
        assert_eq!(
            efi_write_one_in_dir(&dir, "BootOrder-test", &payload, false),
            Err(2)
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn mount_snapshot_is_complete_and_rejects_unknown_rows() {
        let snapshot = "TARGET=\"/\" SOURCE=\"/dev/root\" FSTYPE=\"ext4\"\nTARGET=\"/efi\" SOURCE=\"/dev/sda1\" FSTYPE=\"vfat\"\n";
        assert_eq!(
            mount_candidates(snapshot),
            Ok(vec![(String::from("/efi"), String::from("/dev/sda1"))])
        );
        let unknown = "BROKEN\nTARGET=\"/efi\" SOURCE=\"/dev/sda1\" FSTYPE=\"vfat\"\n";
        assert!(mount_candidates(unknown).is_err());
        let duplicate = "TARGET=\"/boot\" SOURCE=\"/dev/sda1\" FSTYPE=\"vfat\"\nTARGET=\"/boot\" SOURCE=\"/dev/sda2\" FSTYPE=\"ext4\"\n";
        assert!(mount_candidates(duplicate).is_err());
    }
}
