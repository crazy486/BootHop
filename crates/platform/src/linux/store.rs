use crate::ProtectedStore;
use boothop_core::{Error, RecordState, TargetRecord, decode_record, encode_record};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenKind {
    Directory,
    ExistingFile,
    ExclusiveTemp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u64,
    pub inode: u64,
    pub device: u64,
    pub size: u64,
}

/// A narrow syscall boundary for trusted backend implementations, not GUI input.
/// Every opened handle must be CLOEXEC and NOFOLLOW; directory opens require DIRECTORY,
/// existing-file opens must never create, and exclusive temporary opens request mode 0600.
/// Names supplied by LockedStore are single relative components. Lock must be EX|NB.
/// Handles own their descriptors, and closing a locked handle releases its lock.
pub trait Filesystem {
    type Handle;
    fn root(&self) -> Result<Self::Handle, i32>;
    fn open(&self, dir: &Self::Handle, name: &str, kind: OpenKind) -> Result<Self::Handle, i32>;
    fn metadata(&self, file: &Self::Handle) -> Result<Metadata, i32>;
    fn lock(&self, file: &mut Self::Handle) -> Result<(), i32>;
    fn read(&self, file: &mut Self::Handle, bytes: &mut [u8]) -> Result<usize, i32>;
    fn write(&self, file: &mut Self::Handle, bytes: &[u8]) -> Result<usize, i32>;
    fn sync(&self, file: &Self::Handle) -> Result<(), i32>;
    fn rename(&self, dir: &Self::Handle, from: &str, to: &str) -> Result<(), i32>;
    fn unlink(&self, dir: &Self::Handle, name: &str) -> Result<(), i32>;
}

const MAX_RECORD_BYTES: usize = 1_048_576;
const RECORD: &str = "targets.json";
const LOCK: &str = "operation.lock";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The guard itself is the store: load/save cannot be called without the operation lock.
pub struct LockedStore<F: Filesystem> {
    fs: F,
    dir: F::Handle,
    _lock: F::Handle,
}
impl<F: Filesystem> LockedStore<F> {
    pub fn acquire(fs: F) -> Result<Self, Error> {
        let mut dir = fs.root().map_err(|e| io("open", e))?;
        validate_directory(fs.metadata(&dir).map_err(|e| io("metadata", e))?, false)?;
        for component in ["var", "lib", "boothop"] {
            dir = fs
                .open(&dir, component, OpenKind::Directory)
                .map_err(|e| io("open", e))?;
            validate_directory(
                fs.metadata(&dir).map_err(|e| io("metadata", e))?,
                component == "boothop",
            )?;
        }
        let mut lock = fs
            .open(&dir, LOCK, OpenKind::ExistingFile)
            .map_err(|e| io("open", e))?;
        validate_file(fs.metadata(&lock).map_err(|e| io("metadata", e))?)?;
        fs.lock(&mut lock).map_err(|e| {
            if e == rustix::io::Errno::WOULDBLOCK.raw_os_error() {
                Error::Busy
            } else {
                io("lock", e)
            }
        })?;
        Ok(Self {
            fs,
            dir,
            _lock: lock,
        })
    }
}
impl<F: Filesystem> ProtectedStore for LockedStore<F> {
    fn load(&mut self) -> Result<RecordState, Error> {
        let mut file = match self.fs.open(&self.dir, RECORD, OpenKind::ExistingFile) {
            Ok(file) => file,
            Err(2) => return Ok(RecordState::Missing),
            Err(e) => return Err(io("open", e)),
        };
        let meta = self.fs.metadata(&file).map_err(|e| io("metadata", e))?;
        validate_file(meta)?;
        if meta.size > MAX_RECORD_BYTES as u64 {
            return Err(Error::ResourceLimit);
        }
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let limit = buffer.len().min(MAX_RECORD_BYTES - bytes.len() + 1);
            let count = self
                .fs
                .read(&mut file, &mut buffer[..limit])
                .map_err(|e| io("read", e))?;
            if count == 0 {
                break;
            }
            if count > buffer.len() || bytes.len() + count > MAX_RECORD_BYTES {
                return Err(Error::ResourceLimit);
            }
            bytes.try_reserve(count).map_err(|_| Error::ResourceLimit)?;
            bytes.extend_from_slice(&buffer[..count]);
        }
        if bytes.len() as u64 != meta.size
            || self.fs.metadata(&file).map_err(|e| io("metadata", e))? != meta
        {
            return Err(io("read", 5));
        }
        decode_record(&bytes).map(RecordState::Ready)
    }
    fn save(&mut self, target: &TargetRecord) -> Result<(), Error> {
        self.load()?;
        let bytes = encode_record(target)?;
        let name = format!(
            ".targets-{}-{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let mut file = self
            .fs
            .open(&self.dir, &name, OpenKind::ExclusiveTemp)
            .map_err(|e| io("open", e))?;
        let result = (|| {
            validate_file(self.fs.metadata(&file).map_err(|e| io("metadata", e))?)?;
            let mut written = 0;
            while written < bytes.len() {
                let count = self
                    .fs
                    .write(&mut file, &bytes[written..])
                    .map_err(|e| io("write", e))?;
                if count == 0 || count > bytes.len() - written {
                    return Err(io("write", 5));
                }
                written += count;
            }
            self.fs.sync(&file).map_err(|e| io("fsync", e))?;
            self.fs
                .rename(&self.dir, &name, RECORD)
                .map_err(|e| io("rename", e))
        })();
        if let Err(error) = result {
            self.cleanup_temp(&file, &name);
            return Err(error);
        }
        self.fs
            .sync(&self.dir)
            .map_err(|raw_code| Error::StoreDurabilityUnknown { raw_code })
    }
}

impl<F: Filesystem> LockedStore<F> {
    // A cleanup failure must not replace the original save error. If identity or protection
    // cannot be confirmed, leave the name alone for installer/administrator inspection.
    fn cleanup_temp(&self, file: &F::Handle, name: &str) {
        let Ok(owned) = self.fs.metadata(file) else {
            return;
        };
        if validate_file(owned).is_err() {
            return;
        }
        let Ok(named) = self.fs.open(&self.dir, name, OpenKind::ExistingFile) else {
            return;
        };
        let Ok(current) = self.fs.metadata(&named) else {
            return;
        };
        if validate_file(current).is_ok()
            && owned.inode == current.inode
            && owned.device == current.device
        {
            let _ = self.fs.unlink(&self.dir, name);
        }
    }
}

fn io(operation: &'static str, raw_code: i32) -> Error {
    Error::PlatformIo {
        operation: operation.into(),
        raw_code,
    }
}

fn validate_directory(meta: Metadata, protected: bool) -> Result<(), Error> {
    if meta.uid != 0
        || meta.gid != 0
        || meta.mode & 0o170000 != 0o040000
        || meta.mode & 0o022 != 0
        || (protected && meta.mode & 0o7777 != 0o700)
    {
        // A successful stat with untrusted metadata is a policy denial (EPERM).
        return Err(io("metadata", 1));
    }
    Ok(())
}

fn validate_file(meta: Metadata) -> Result<(), Error> {
    if meta.uid != 0 || meta.gid != 0 || meta.mode != 0o100600 || meta.links != 1 {
        // No syscall failed here; use EPERM for the explicit protection-policy denial.
        return Err(io("metadata", 1));
    }
    Ok(())
}

/// Fixed installation path only. Construction performs validation and acquires the lock.
/// Callers keep this value alive through the entire operation, including error reporting.
pub struct LinuxStore(LockedStore<LinuxSyscalls>);
impl LinuxStore {
    pub fn open() -> Result<Self, Error> {
        LockedStore::acquire(LinuxSyscalls).map(Self)
    }
}
impl ProtectedStore for LinuxStore {
    fn load(&mut self) -> Result<RecordState, Error> {
        self.0.load()
    }
    fn save(&mut self, target: &TargetRecord) -> Result<(), Error> {
        self.0.save(target)
    }
}

struct LinuxSyscalls;
impl Filesystem for LinuxSyscalls {
    type Handle = std::os::fd::OwnedFd;
    fn root(&self) -> Result<Self::Handle, i32> {
        rustix::fs::open(
            "/",
            open_flags(OpenKind::Directory),
            rustix::fs::Mode::empty(),
        )
        .map_err(raw)
    }
    fn open(&self, dir: &Self::Handle, name: &str, kind: OpenKind) -> Result<Self::Handle, i32> {
        rustix::fs::openat(
            dir,
            name,
            open_flags(kind),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(raw)
    }
    fn metadata(&self, file: &Self::Handle) -> Result<Metadata, i32> {
        let stat = rustix::fs::fstat(file).map_err(raw)?;
        Ok(Metadata {
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            links: stat.st_nlink as u64,
            inode: stat.st_ino,
            device: stat.st_dev,
            size: stat.st_size as u64,
        })
    }
    fn lock(&self, file: &mut Self::Handle) -> Result<(), i32> {
        rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(raw)
    }
    fn read(&self, file: &mut Self::Handle, bytes: &mut [u8]) -> Result<usize, i32> {
        rustix::io::read(file, bytes).map_err(raw)
    }
    fn write(&self, file: &mut Self::Handle, bytes: &[u8]) -> Result<usize, i32> {
        rustix::io::write(file, bytes).map_err(raw)
    }
    fn sync(&self, file: &Self::Handle) -> Result<(), i32> {
        rustix::fs::fsync(file).map_err(raw)
    }
    fn rename(&self, dir: &Self::Handle, from: &str, to: &str) -> Result<(), i32> {
        rustix::fs::renameat(dir, from, dir, to).map_err(raw)
    }
    fn unlink(&self, dir: &Self::Handle, name: &str) -> Result<(), i32> {
        rustix::fs::unlinkat(dir, name, rustix::fs::AtFlags::empty()).map_err(raw)
    }
}

fn open_flags(kind: OpenKind) -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    OFlags::CLOEXEC
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | match kind {
            OpenKind::Directory => OFlags::RDONLY | OFlags::DIRECTORY,
            OpenKind::ExistingFile => OFlags::RDONLY,
            OpenKind::ExclusiveTemp => OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        }
}
fn raw(error: rustix::io::Errno) -> i32 {
    error.raw_os_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File, OpenOptions},
        os::{
            fd::OwnedFd,
            unix::fs::{MetadataExt, OpenOptionsExt, symlink},
        },
        path::PathBuf,
    };

    // Native syscalls only, against objects exclusively created by this test process.
    // Never constructs the fixed-path store and never certifies root-owned deployment.
    struct TemporaryDirectory(PathBuf);
    impl TemporaryDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "boothop-store-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn fd(&self) -> OwnedFd {
            File::open(&self.0).unwrap().into()
        }
        fn file(&self, name: &str, bytes: &[u8]) {
            use std::io::Write;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(self.0.join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
        }
    }
    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn native_open_is_nofollow_cloexec_and_temp_creation_exclusive() {
        let temp = TemporaryDirectory::new();
        let dir = temp.fd();
        let sys = LinuxSyscalls;
        assert_eq!(
            sys.open(&dir, "operation.lock", OpenKind::ExistingFile)
                .unwrap_err(),
            2
        );
        assert!(!temp.0.join("operation.lock").exists());
        temp.file("operation.lock", b"persistent");
        let lock = sys
            .open(&dir, "operation.lock", OpenKind::ExistingFile)
            .unwrap();
        assert!(
            rustix::io::fcntl_getfd(&lock)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rustix::fs::fcntl_getfl(&lock)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
        assert_eq!(
            sys.open(&dir, "operation.lock", OpenKind::ExclusiveTemp)
                .unwrap_err(),
            17
        );
        assert_eq!(
            fs::read(temp.0.join("operation.lock")).unwrap(),
            b"persistent"
        );
        symlink("operation.lock", temp.0.join("link")).unwrap();
        assert_eq!(
            sys.open(&dir, "link", OpenKind::ExistingFile).unwrap_err(),
            40
        );
        symlink(".", temp.0.join("dir-link")).unwrap();
        assert!(sys.open(&dir, "dir-link", OpenKind::Directory).is_err());
        fs::create_dir(temp.0.join("child")).unwrap();
        let child = sys.open(&dir, "child", OpenKind::Directory).unwrap();
        assert!(
            rustix::io::fcntl_getfd(&child)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
    }

    #[test]
    fn native_lock_is_nonblocking_and_released_by_descriptor_drop() {
        let temp = TemporaryDirectory::new();
        temp.file("operation.lock", b"");
        let dir = temp.fd();
        let sys = LinuxSyscalls;
        let mut first = sys
            .open(&dir, "operation.lock", OpenKind::ExistingFile)
            .unwrap();
        let mut second = sys
            .open(&dir, "operation.lock", OpenKind::ExistingFile)
            .unwrap();
        sys.lock(&mut first).unwrap();
        assert_eq!(sys.lock(&mut second), Err(11));
        drop(first);
        sys.lock(&mut second).unwrap();
        drop(second);
        assert_eq!(fs::read(temp.0.join("operation.lock")).unwrap(), b"");
    }

    #[test]
    fn native_replace_sync_and_cleanup_leave_persistent_lock_unchanged() {
        let temp = TemporaryDirectory::new();
        temp.file("operation.lock", b"");
        temp.file("targets.json", b"old");
        let dir = temp.fd();
        let sys = LinuxSyscalls;
        let inode = fs::metadata(temp.0.join("operation.lock")).unwrap().ino();
        let mut lock = sys
            .open(&dir, "operation.lock", OpenKind::ExistingFile)
            .unwrap();
        sys.lock(&mut lock).unwrap();
        let mut new = sys
            .open(&dir, "private.tmp", OpenKind::ExclusiveTemp)
            .unwrap();
        assert_eq!(sys.metadata(&new).unwrap().mode, 0o100600);
        assert_eq!(sys.write(&mut new, b"replacement"), Ok(11));
        sys.sync(&new).unwrap();
        assert_eq!(fs::read(temp.0.join("targets.json")).unwrap(), b"old");
        sys.rename(&dir, "private.tmp", "targets.json").unwrap();
        sys.sync(&dir).unwrap();
        assert_eq!(
            fs::read(temp.0.join("targets.json")).unwrap(),
            b"replacement"
        );
        let mut read = sys
            .open(&dir, "targets.json", OpenKind::ExistingFile)
            .unwrap();
        let mut buffer = [0; 32];
        assert_eq!(sys.read(&mut read, &mut buffer), Ok(11));
        assert_eq!(&buffer[..11], b"replacement");
        assert_eq!(sys.write(&mut read, b"bad"), Err(9));
        let leftover = sys
            .open(&dir, "leftover.tmp", OpenKind::ExclusiveTemp)
            .unwrap();
        drop(leftover);
        sys.unlink(&dir, "leftover.tmp").unwrap();
        assert!(!temp.0.join("leftover.tmp").exists());
        assert_eq!(
            fs::metadata(temp.0.join("operation.lock")).unwrap().ino(),
            inode
        );
        let mut second = sys
            .open(&dir, "operation.lock", OpenKind::ExistingFile)
            .unwrap();
        assert_eq!(sys.lock(&mut second), Err(11));
    }
}
