#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenKind {
    Directory,
    ReadVariable,
    CreateNext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub mode: u32,
    pub filesystem: u64,
    pub readonly: bool,
    pub size: u64,
    pub device: u64,
    pub inode: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}
use super::LinuxCalls;
use boothop_core::{BootId, Error, PlatformOperation};
pub(crate) const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
fn reserve<T>(buffer: &mut Vec<T>, additional: usize) -> Result<(), Error> {
    buffer
        .try_reserve(additional)
        .map_err(|_| Error::ResourceLimit)
}
pub(crate) fn io(operation: &'static str, raw_code: i32) -> Error {
    Error::PlatformIo {
        operation: PlatformOperation::from_label(operation).expect("closed Linux operation label"),
        raw_code,
    }
}

const EFIVARFS: u64 = 0xde5e81e4;
const MAX_RAW: usize = 1_048_580;
pub(crate) fn directory<C: LinuxCalls>(calls: &mut C) -> Result<C::Handle, Error> {
    let mut dir = calls.root().map_err(|e| io("open", e))?;
    validate(
        calls.metadata(&dir).map_err(|e| io("metadata", e))?,
        true,
        false,
    )?;
    for name in ["sys", "firmware", "efi", "efivars"] {
        dir = calls
            .open(&dir, name, OpenKind::Directory)
            .map_err(|e| io("open", e))?;
        validate(
            calls.metadata(&dir).map_err(|e| io("metadata", e))?,
            true,
            name == "efivars",
        )?;
    }
    Ok(dir)
}
pub(crate) fn read_next<C: LinuxCalls>(calls: &mut C) -> Result<Option<BootId>, Error> {
    let dir = directory(calls)?;
    read_variable(calls, &dir, "BootNext", true)?
        .map(|b| decode_boot_next(&b))
        .transpose()
}

fn validate(meta: Metadata, directory: bool, efivarfs: bool) -> Result<(), Error> {
    if meta.mode & 0o170000 != if directory { 0o040000 } else { 0o100000 } {
        return Err(io("metadata", 1));
    }
    if efivarfs && meta.filesystem != EFIVARFS {
        return Err(io("metadata", 19));
    }
    if efivarfs && meta.readonly {
        return Err(io("metadata", 30));
    }
    Ok(())
}
fn read_variable<C: LinuxCalls>(
    calls: &mut C,
    dir: &C::Handle,
    stem: &str,
    optional: bool,
) -> Result<Option<Vec<u8>>, Error> {
    let mut fd = match calls.open(dir, &format!("{stem}-{GUID}"), OpenKind::ReadVariable) {
        Ok(fd) => fd,
        Err(2) if optional => return Ok(None),
        Err(e) => return Err(io("open", e)),
    };
    let before = calls.metadata(&fd).map_err(|e| io("metadata", e))?;
    validate(before, false, true)?;
    if before.size > MAX_RAW as u64 {
        return Err(Error::ResourceLimit);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(io("read", 110));
        }
        let limit = buffer.len().min(MAX_RAW - bytes.len() + 1);
        // EINTR is returned immediately. In particular no write is ever retried.
        let count = calls
            .read(&mut fd, &mut buffer[..limit])
            .map_err(|e| io("read", e))?;
        if count == 0 {
            break;
        }
        if count > limit || bytes.len() + count > MAX_RAW {
            return Err(Error::ResourceLimit);
        }
        reserve(&mut bytes, count)?;
        bytes.extend_from_slice(&buffer[..count]);
    }
    if before.size != bytes.len() as u64
        || before != calls.metadata(&fd).map_err(|e| io("metadata", e))?
    {
        return Err(io("read", 5));
    }
    let named = calls
        .open(dir, &format!("{stem}-{GUID}"), OpenKind::ReadVariable)
        .map_err(|e| io("open", e))?;
    if before != calls.metadata(&named).map_err(|e| io("metadata", e))? {
        return Err(io("read", 5));
    }
    Ok(Some(bytes))
}
fn payload(bytes: &[u8], attributes: u32) -> Result<&[u8], Error> {
    if bytes.get(..4) != Some(attributes.to_le_bytes().as_slice()) {
        return Err(Error::UnsupportedFormat);
    }
    Ok(&bytes[4..])
}
fn decode_boot_next(bytes: &[u8]) -> Result<BootId, Error> {
    decode_id(bytes, 7)
}
fn decode_id(bytes: &[u8], attributes: u32) -> Result<BootId, Error> {
    let payload = payload(bytes, attributes)?;
    let pair: [u8; 2] = payload.try_into().map_err(|_| Error::UnsupportedFormat)?;
    Ok(BootId(u16::from_le_bytes(pair)))
}
pub(crate) fn read_options<C: LinuxCalls>(
    calls: &mut C,
) -> Result<boothop_core::OptionInventory, Error> {
    use boothop_core::{EnumerationDiagnostic, OptionInventory, parse_load_option};
    let dir = directory(calls)?;
    let directory_before = calls.metadata(&dir).map_err(|e| io("metadata", e))?;
    let mut total = 0usize;
    let mut read = |calls: &mut C, stem: &str, optional| -> Result<Option<Vec<u8>>, Error> {
        let bytes = read_variable(calls, &dir, stem, optional)?;
        total = total
            .checked_add(bytes.as_ref().map_or(0, Vec::len))
            .ok_or(Error::ResourceLimit)?;
        if total > 1_048_576 {
            return Err(Error::ResourceLimit);
        }
        Ok(bytes)
    };
    let order = read(calls, "BootOrder", false)?.ok_or(Error::TargetMissing)?;
    let order = payload(&order, 7)?;
    if order.len() % 2 != 0 {
        return Err(Error::UnsupportedFormat);
    }
    if order.len() / 2 > 65536 {
        return Err(Error::ResourceLimit);
    }
    // Fixed bitsets bound deduplication by the u16 domain and preserve first occurrence order.
    let mut referenced = [false; 65536];
    let mut duplicated = [false; 65536];
    let mut diagnostics = Vec::new();
    for pair in order.as_chunks::<2>().0 {
        let id = u16::from_le_bytes([pair[0], pair[1]]);
        if referenced[id as usize] && !duplicated[id as usize] {
            reserve(&mut diagnostics, 1)?;
            diagnostics.push(EnumerationDiagnostic::DuplicateBootOrder(BootId(id)));
            duplicated[id as usize] = true;
        }
        referenced[id as usize] = true;
    }
    let current = read(calls, "BootCurrent", false)?.ok_or(Error::TargetMissing)?;
    referenced[decode_id(&current, 6)?.0 as usize] = true;
    let names = calls.names(&dir)?;
    let mut discovered = [false; 65536];
    for name in names {
        if let Some(id) = boot_id(&name) {
            discovered[id.0 as usize] = true;
        }
    }
    if referenced
        .iter()
        .zip(discovered)
        .any(|(reference, found)| *reference && !found)
    {
        return Err(Error::TargetMissing);
    }
    let mut entries = Vec::new();
    for (id, found) in discovered.into_iter().enumerate() {
        if !found {
            continue;
        }
        let bytes = read(calls, &format!("Boot{id:04X}"), false)?.ok_or(Error::TargetMissing)?;
        let option = parse_load_option(payload(&bytes, 7)?)?;
        reserve(&mut entries, 1)?;
        entries.push((BootId(id as u16), option));
    }
    if directory_before != calls.metadata(&dir).map_err(|e| io("metadata", e))? {
        return Err(io("read", 5));
    }
    Ok(OptionInventory {
        entries,
        diagnostics,
    })
}

fn boot_id(name: &[u8]) -> Option<BootId> {
    if name.len() != 45 || &name[..4] != b"Boot" || name[8] != b'-' || &name[9..] != GUID.as_bytes()
    {
        return None;
    }
    let mut id = 0u16;
    for byte in &name[4..8] {
        id = id * 16
            + match byte {
                b'0'..=b'9' => (byte - b'0') as u16,
                b'A'..=b'F' => (byte - b'A' + 10) as u16,
                _ => return None,
            };
    }
    Some(BootId(id))
}
pub(crate) fn write_next<C: LinuxCalls>(calls: &mut C, target: BootId) -> Result<(), Error> {
    let dir = directory(calls)?;
    let mut fd = calls
        .open(&dir, &format!("BootNext-{GUID}"), OpenKind::CreateNext)
        .map_err(|e| io("open", e))?;
    validate(
        calls.metadata(&fd).map_err(|e| io("metadata", e))?,
        false,
        true,
    )?;
    let [low, high] = target.0.to_le_bytes();
    let count = calls
        .write(&mut fd, &[7, 0, 0, 0, low, high])
        .map_err(|e| io("write", e))?;
    if count != 6 {
        return Err(io("write", 5));
    }
    Ok(())
}
pub(crate) fn native_open(
    dir: &std::os::fd::OwnedFd,
    name: &str,
    kind: OpenKind,
) -> Result<std::os::fd::OwnedFd, i32> {
    rustix::fs::openat(
        dir,
        name,
        open_flags(kind),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|e| e.raw_os_error())
}
pub(crate) fn native_names(dir: &std::os::fd::OwnedFd) -> Result<Vec<Vec<u8>>, Error> {
    let directory = rustix::fs::Dir::read_from(dir).map_err(|e| io("read", e.raw_os_error()))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut names = Vec::new();
    for entry in directory {
        if std::time::Instant::now() >= deadline {
            return Err(io("read", 110));
        }
        let entry = entry.map_err(|e| io("read", e.raw_os_error()))?;
        let bytes = entry.file_name().to_bytes();
        if boot_id(bytes).is_none() {
            continue;
        }
        if names.len() == 65536 {
            return Err(Error::ResourceLimit);
        }
        let mut name = Vec::new();
        reserve(&mut name, bytes.len())?;
        name.extend_from_slice(bytes);
        reserve(&mut names, 1)?;
        names.push(name);
    }
    Ok(names)
}
pub(crate) fn open_flags(kind: OpenKind) -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    OFlags::CLOEXEC
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | match kind {
            OpenKind::Directory => OFlags::RDONLY | OFlags::DIRECTORY,
            OpenKind::ReadVariable => OFlags::RDONLY,
            OpenKind::CreateNext => OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        }
}
pub(crate) fn native_metadata(fd: &std::os::fd::OwnedFd) -> Result<Metadata, i32> {
    let stat = rustix::fs::fstat(fd).map_err(|e| e.raw_os_error())?;
    let fs = rustix::fs::fstatfs(fd).map_err(|e| e.raw_os_error())?;
    let vfs = rustix::fs::fstatvfs(fd).map_err(|e| e.raw_os_error())?;
    Ok(Metadata {
        mode: stat.st_mode,
        filesystem: fs.f_type as u64,
        readonly: vfs.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY),
        size: stat.st_size as u64,
        device: stat.st_dev,
        inode: stat.st_ino,
        mtime: (stat.st_mtime, stat.st_mtime_nsec as i64),
        ctime: (stat.st_ctime, stat.st_ctime_nsec as i64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File},
        os::{
            fd::OwnedFd,
            unix::fs::{MetadataExt, symlink},
        },
        sync::atomic::{AtomicU64, Ordering},
    };
    static SEQ: AtomicU64 = AtomicU64::new(0);
    #[test]
    fn allocation_failure_is_resource_limit_without_partial_buffer_change() {
        let mut bytes = vec![7u8, 0, 0, 0];
        assert_eq!(reserve(&mut bytes, usize::MAX), Err(Error::ResourceLimit));
        assert_eq!(bytes, [7, 0, 0, 0]);
    }
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "boothop-firmware-unit-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
        fn fd(&self) -> OwnedFd {
            File::open(&self.0).unwrap().into()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    // Only isolated ordinary temporary descriptors. No SystemLinuxCalls construction.
    #[test]
    fn native_descriptor_opens_are_exclusive_nofollow_cloexec_and_not_truncating() {
        let temp = Temp::new();
        let dir = temp.fd();
        let mut fd = native_open(&dir, "synthetic", OpenKind::CreateNext).unwrap();
        assert!(
            rustix::io::fcntl_getfd(&fd)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        let flags = rustix::fs::fcntl_getfl(&fd).unwrap();
        assert!(!flags.intersects(rustix::fs::OFlags::TRUNC | rustix::fs::OFlags::APPEND));
        assert_eq!(rustix::io::write(&mut fd, &[7, 0, 0, 0, 3, 0]).unwrap(), 6);
        assert_eq!(
            native_open(&dir, "synthetic", OpenKind::CreateNext).unwrap_err(),
            17
        );
        assert_eq!(
            fs::read(temp.0.join("synthetic")).unwrap(),
            [7, 0, 0, 0, 3, 0]
        );
        symlink("synthetic", temp.0.join("link")).unwrap();
        assert_eq!(
            native_open(&dir, "link", OpenKind::ReadVariable).unwrap_err(),
            40
        );
        let mut read = native_open(&dir, "synthetic", OpenKind::ReadVariable).unwrap();
        assert!(
            rustix::io::fcntl_getfd(&read)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert_eq!(
            rustix::io::write(&mut read, b"x")
                .unwrap_err()
                .raw_os_error(),
            9
        );
        fs::create_dir(temp.0.join("child")).unwrap();
        symlink("child", temp.0.join("dirlink")).unwrap();
        assert!(native_open(&dir, "dirlink", OpenKind::Directory).is_err());
        assert!(native_open(&dir, "synthetic", OpenKind::Directory).is_err());
    }

    #[test]
    fn native_metadata_keeps_type_filesystem_and_nanosecond_change_stamps() {
        let temp = Temp::new();
        let file = File::create(temp.0.join("synthetic")).unwrap();
        file.set_times(
            fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::new(123, 456)),
        )
        .unwrap();
        let expected = file.metadata().unwrap();
        let fd: OwnedFd = file.into();
        let meta = native_metadata(&fd).unwrap();
        assert_eq!(meta.mode & 0o170000, 0o100000);
        assert_ne!(meta.filesystem, EFIVARFS);
        assert_eq!(meta.mtime, (123, 456));
        assert_eq!(meta.ctime, (expected.ctime(), expected.ctime_nsec()));
        assert_eq!(meta.size, 0);
        assert_eq!(meta.device, expected.dev());
        assert_eq!(meta.inode, expected.ino());
        assert_eq!(validate(meta, false, true), Err(io("metadata", 19)));
    }
    #[test]
    fn native_enumeration_uses_descriptor_and_strict_names() {
        let temp = Temp::new();
        for stem in ["Boot0001", "Boot000a", "Boot000A", "BootNext", "Boot00011"] {
            File::create(temp.0.join(format!("{stem}-{GUID}"))).unwrap();
        }
        let mut names = native_names(&temp.fd()).unwrap();
        names.sort();
        assert_eq!(
            names,
            [
                b"Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c".to_vec(),
                b"Boot000A-8be4df61-93ca-11d2-aa0d-00e098032b8c".to_vec()
            ]
        );
        let regular: OwnedFd = File::open(temp.0.join(format!("Boot0001-{GUID}")))
            .unwrap()
            .into();
        assert_eq!(native_names(&regular), Err(io("read", 20)));
    }
}
