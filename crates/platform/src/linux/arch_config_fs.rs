use std::{
    ffi::OsStr,
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::Path,
};

use super::uki::ArchConfigFs;

const MAX_FILE_BYTES: usize = 1_048_576;
const MAX_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_DIRECTORY_NAME_BYTES: usize = 255;
const MOUNTINFO: &str = "/proc/self/mountinfo";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryType {
    RegularFile,
    Directory,
    Other,
}

/// Minimal read-only syscall surface for Arch configuration discovery.
/// Implementations must open components relative to the supplied directory with NOFOLLOW.
pub trait ArchConfigFsCalls {
    type Handle;

    fn root(&self) -> Result<Self::Handle, i32>;
    fn open_directory(&self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32>;
    fn open_file(&self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32>;
    fn entry_type(&self, handle: &Self::Handle) -> Result<EntryType, i32>;
    fn names(&self, directory: &Self::Handle) -> Result<Vec<Vec<u8>>, String>;
    fn read(&self, file: &mut Self::Handle, buffer: &mut [u8]) -> Result<usize, i32>;
}

/// Concrete filesystem adapter with an injectable, read-only syscall boundary.
pub struct ArchConfigFsAdapter<C: ArchConfigFsCalls = SystemArchConfigFsCalls> {
    calls: C,
    root: C::Handle,
}

impl ArchConfigFsAdapter<SystemArchConfigFsCalls> {
    /// Constructs the production view rooted at `/`. It performs no reads until queried.
    pub fn system() -> Result<Self, String> {
        Self::rooted_at("/")
    }

    /// Opens a directory as the filesystem root. Intended for isolated tests and embedding.
    pub fn rooted_at(path: impl AsRef<Path>) -> Result<Self, String> {
        Self::new(SystemArchConfigFsCalls::new(path))
    }
}

impl<C: ArchConfigFsCalls> ArchConfigFsAdapter<C> {
    pub fn new(calls: C) -> Result<Self, String> {
        let root = calls.root().map_err(|error| io_error("open root", error))?;
        if calls
            .entry_type(&root)
            .map_err(|error| io_error("inspect root", error))?
            != EntryType::Directory
        {
            return Err("filesystem root is not a directory".into());
        }
        Ok(Self { calls, root })
    }

    fn open_path(&self, path: &str, final_type: EntryType) -> Result<Option<C::Handle>, String> {
        let components = path_components(path)?;
        let Some((last, parents)) = components.split_last() else {
            return Err("root is not a regular file".into());
        };
        let mut parent = None;
        for component in parents {
            let result = match parent.as_ref() {
                Some(dir) => self.calls.open_directory(dir, component),
                None => self.calls.open_directory(&self.root, component),
            };
            match result {
                Ok(next) => parent = Some(next),
                Err(error) if is_not_found(error) => return Ok(None),
                Err(error) => return Err(io_error("open directory", error)),
            }
        }
        let parent = parent.as_ref().unwrap_or(&self.root);
        let opened = if final_type == EntryType::Directory {
            self.calls.open_directory(&parent, last)
        } else {
            self.calls.open_file(&parent, last)
        };
        let handle = match opened {
            Ok(handle) => handle,
            Err(error) if is_not_found(error) => return Ok(None),
            Err(error) => return Err(io_error("open input", error)),
        };
        let found = self
            .calls
            .entry_type(&handle)
            .map_err(|error| io_error("inspect input", error))?;
        if found != final_type {
            return Err("input has an unsupported file type".into());
        }
        Ok(Some(handle))
    }

    fn read_path(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let Some(mut file) = self.open_path(path, EntryType::RegularFile)? else {
            return Ok(None);
        };
        read_bounded(&self.calls, &mut file).map(Some)
    }
}

impl ArchConfigFsCalls for SystemArchConfigFsCalls {
    type Handle = OwnedFd;

    fn root(&self) -> Result<Self::Handle, i32> {
        open_root(&self.path)
    }

    fn open_directory(&self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
        native_open(parent, name, true)
    }

    fn open_file(&self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
        native_open(parent, name, false)
    }

    fn entry_type(&self, handle: &Self::Handle) -> Result<EntryType, i32> {
        let stat = rustix::fs::fstat(handle).map_err(|error| error.raw_os_error())?;
        Ok(match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
            rustix::fs::FileType::RegularFile => EntryType::RegularFile,
            rustix::fs::FileType::Directory => EntryType::Directory,
            _ => EntryType::Other,
        })
    }

    fn names(&self, directory: &Self::Handle) -> Result<Vec<Vec<u8>>, String> {
        let dir = rustix::fs::Dir::read_from(directory)
            .map_err(|error| io_error("read directory", error.raw_os_error()))?;
        let mut entries = Vec::new();
        let mut name_bytes = 0usize;
        for entry in dir {
            let entry = entry.map_err(|error| io_error("read directory", error.raw_os_error()))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if name.is_empty() || name.len() > MAX_DIRECTORY_NAME_BYTES {
                return Err("directory contains an invalid or oversized name".into());
            }
            if entries.len() == MAX_DIRECTORY_ENTRIES {
                return Err("directory entry limit exceeded".into());
            }
            name_bytes = name_bytes
                .checked_add(name.len())
                .ok_or_else(|| "directory size limit exceeded".to_string())?;
            if name_bytes > MAX_FILE_BYTES {
                return Err("directory size limit exceeded".into());
            }
            entries.push(name.to_vec());
        }
        Ok(entries)
    }

    fn read(&self, file: &mut Self::Handle, buffer: &mut [u8]) -> Result<usize, i32> {
        rustix::io::read(file, buffer).map_err(|error| error.raw_os_error())
    }
}

impl<C: ArchConfigFsCalls> ArchConfigFs for ArchConfigFsAdapter<C> {
    fn read_text(&self, path: &str) -> Result<Option<String>, String> {
        self.read_path(path)?
            .map(|bytes| {
                String::from_utf8(bytes).map_err(|_| "input is not valid UTF-8".to_string())
            })
            .transpose()
    }
    fn is_file(&self, path: &str) -> bool {
        matches!(self.open_path(path, EntryType::RegularFile), Ok(Some(_)))
    }
    fn is_directory(&self, path: &str) -> bool {
        matches!(self.open_path(path, EntryType::Directory), Ok(Some(_)))
    }
    fn is_mounted_esp(&self, mount_path: &str) -> bool {
        if mount_path == "/" {
            return false;
        }
        let Ok(_) = path_components(mount_path) else {
            return false;
        };
        let Ok(Some(bytes)) = self.read_path(MOUNTINFO) else {
            return false;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return false;
        };
        let Ok(mounts) = parse_mountinfo(text) else {
            return false;
        };
        let matching = mounts
            .iter()
            .filter(|(path, _)| path == mount_path)
            .collect::<Vec<_>>();
        matching.len() == 1 && matching[0].1.eq_ignore_ascii_case("vfat")
    }
    fn files_in_directory(&self, path: &str) -> Result<Vec<String>, String> {
        let Some(directory) = self.open_path(path, EntryType::Directory)? else {
            return Err("directory is missing".into());
        };
        let names = self.calls.names(&directory)?;
        if names.len() > MAX_DIRECTORY_ENTRIES
            || names.iter().any(|name| {
                name.is_empty()
                    || name.len() > MAX_DIRECTORY_NAME_BYTES
                    || name == b"."
                    || name == b".."
                    || name.contains(&b'/')
            })
            || names
                .iter()
                .try_fold(0usize, |size, name| size.checked_add(name.len()))
                .is_none_or(|size| size > MAX_FILE_BYTES)
        {
            return Err("directory entry limit exceeded or invalid name".into());
        }
        names
            .into_iter()
            .map(|name| {
                String::from_utf8(name)
                    .map_err(|_| "directory contains a non-UTF-8 name".to_string())
            })
            .collect()
    }
}

/// Production syscall implementation. It only opens existing paths with read-only flags.
pub struct SystemArchConfigFsCalls {
    path: std::path::PathBuf,
}

impl SystemArchConfigFsCalls {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

fn path_components(path: &str) -> Result<Vec<&str>, String> {
    if path.len() > 4_096
        || !path.starts_with('/')
        || path.ends_with('/') && path != "/"
        || path.contains("//")
    {
        return Err("path must be a normalized absolute path".into());
    }
    if path == "/" {
        return Ok(Vec::new());
    }
    let components = path[1..].split('/').collect::<Vec<_>>();
    if components.iter().any(|part| {
        part.is_empty()
            || part.len() > MAX_DIRECTORY_NAME_BYTES
            || *part == "."
            || *part == ".."
            || part.as_bytes().contains(&0)
    }) {
        return Err("path must be a normalized absolute path".into());
    }
    Ok(components)
}

fn read_bounded<C: ArchConfigFsCalls>(calls: &C, file: &mut C::Handle) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let count = calls
            .read(file, &mut chunk)
            .map_err(|error| io_error("read input", error))?;
        if count == 0 {
            return Ok(bytes);
        }
        let new_len = bytes
            .len()
            .checked_add(count)
            .ok_or_else(|| "input size limit exceeded".to_string())?;
        if new_len > MAX_FILE_BYTES {
            return Err("input size limit exceeded".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

fn parse_mountinfo(text: &str) -> Result<Vec<(String, String)>, String> {
    if text.is_empty() {
        return Err("mount metadata is empty".into());
    }
    let mut mounts = Vec::new();
    for line in text.lines() {
        let (before, after) = line
            .split_once(" - ")
            .ok_or_else(|| "malformed mount metadata".to_string())?;
        let fields = before.split_ascii_whitespace().collect::<Vec<_>>();
        let post = after.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 || post.len() < 3 {
            return Err("malformed mount metadata".into());
        }
        fields[0]
            .parse::<u64>()
            .map_err(|_| "malformed mount ID".to_string())?;
        fields[1]
            .parse::<u64>()
            .map_err(|_| "malformed parent mount ID".to_string())?;
        let (major, minor) = fields[2]
            .split_once(':')
            .ok_or_else(|| "malformed mount device number".to_string())?;
        if major.parse::<u32>().is_err() || minor.parse::<u32>().is_err() {
            return Err("malformed mount device number".into());
        }
        mounts.push((decode_mount_path(fields[4])?, post[0].to_owned()));
    }
    if mounts.is_empty() {
        return Err("mount metadata has no entries".into());
    }
    Ok(mounts)
}

fn decode_mount_path(encoded: &str) -> Result<String, String> {
    let input = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'\\' {
            let digits = input
                .get(index + 1..index + 4)
                .ok_or_else(|| "malformed escaped mount path".to_string())?;
            if !digits.iter().all(|digit| matches!(digit, b'0'..=b'7')) {
                return Err("malformed escaped mount path".into());
            }
            let value = (u16::from(digits[0] - b'0') << 6)
                | (u16::from(digits[1] - b'0') << 3)
                | u16::from(digits[2] - b'0');
            let value = u8::try_from(value)
                .map_err(|_| "escaped mount path byte is out of range".to_string())?;
            if value == 0 {
                return Err("malformed escaped mount path".into());
            }
            decoded.push(value);
            index += 4;
        } else {
            decoded.push(input[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "mount path is not UTF-8".into())
}

fn open_root(path: &Path) -> Result<OwnedFd, i32> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| error.raw_os_error())
}

fn native_open(parent: &OwnedFd, name: &str, directory: bool) -> Result<OwnedFd, i32> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || OsStr::new(name).as_bytes().contains(&0)
    {
        return Err(rustix::io::Errno::INVAL.raw_os_error());
    }
    let mut flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::NONBLOCK;
    if directory {
        flags |= rustix::fs::OFlags::DIRECTORY;
    }
    rustix::fs::openat(parent, name, flags, rustix::fs::Mode::empty())
        .map_err(|error| error.raw_os_error())
}

fn is_not_found(error: i32) -> bool {
    error == rustix::io::Errno::NOENT.raw_os_error()
}
fn io_error(action: &str, error: i32) -> String {
    format!("cannot {action}: OS error {error}")
}
