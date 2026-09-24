//! Untrusted per-user display cache. Descriptor-relative traversal rejects symlinks at every level.
use super::{Cache, CacheError, CachedTarget, StartupDiagnostic, StartupPhase};
use boothop_core::{BootId, Os};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
const LIMIT: usize = 64 * 1024;
const STARTUP_DETAIL_LIMIT: usize = 4096;
static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn resolve_cache_path(
    xdg_state: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf, CacheError> {
    let base = if let Some(xdg) = xdg_state.filter(|p| Path::new(p).is_absolute()) {
        PathBuf::from(xdg)
    } else {
        PathBuf::from(
            home.filter(|p| Path::new(p).is_absolute())
                .ok_or(CacheError::Unavailable)?,
        )
        .join(".local/state")
    };
    let path = base.join("boothop/cache-v1.json");
    validate(&path)?;
    Ok(path)
}
pub struct LinuxCache {
    path: Result<PathBuf, CacheError>,
}
impl LinuxCache {
    pub fn at(path: PathBuf) -> Self {
        Self {
            path: validate(&path).map(|_| path),
        }
    }
    /// Environment is supplied by the production entry point; tests never read the user's HOME.
    pub fn from_environment(xdg_state: Option<&OsStr>, home: Option<&OsStr>) -> Self {
        Self {
            path: resolve_cache_path(xdg_state, home),
        }
    }

    /// Record only bounded, non-sensitive startup state for diagnosing a
    /// detached desktop launch. Failure is deliberately independent of the
    /// Quick Hop result and never changes its control flow.
    pub fn save_startup_diagnostic(
        &self,
        diagnostic: &StartupDiagnostic,
    ) -> Result<(), CacheError> {
        if diagnostic.detail.len() > STARTUP_DETAIL_LIMIT {
            return Err(CacheError::Unavailable);
        }
        let path = self
            .path
            .as_ref()
            .map_err(Clone::clone)?
            .with_file_name("startup-v1.json");
        let data = WireStartup {
            version: 1,
            phase: match diagnostic.phase {
                StartupPhase::Started => WireStartupPhase::Started,
                StartupPhase::BeforeSend => WireStartupPhase::BeforeSend,
                StartupPhase::UnknownAfterSend => WireStartupPhase::UnknownAfterSend,
                StartupPhase::Domain => WireStartupPhase::Domain,
                StartupPhase::RebootRequested => WireStartupPhase::RebootRequested,
                StartupPhase::ShowWindow => WireStartupPhase::ShowWindow,
            },
            detail: diagnostic.detail.clone(),
        };
        let bytes = serde_json::to_vec(&data).map_err(|_| CacheError::Unavailable)?;
        if bytes.len() > LIMIT {
            return Err(CacheError::Unavailable);
        }
        write_atomic(&path, &bytes)
    }
}
fn validate(path: &Path) -> Result<(), CacheError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(CacheError::Unavailable);
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCache {
    version: u8,
    boot_id: u16,
    os: WireOs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description_utf16: Option<Vec<u16>>,
}
#[derive(Serialize, Deserialize)]
enum WireOs {
    Windows,
    Linux,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum WireStartupPhase {
    Started,
    BeforeSend,
    UnknownAfterSend,
    Domain,
    RebootRequested,
    ShowWindow,
}

#[derive(Serialize)]
struct WireStartup {
    version: u8,
    phase: WireStartupPhase,
    detail: String,
}
impl Cache for LinuxCache {
    fn load(&self) -> Result<Option<CachedTarget>, CacheError> {
        let path = self.path.as_ref().map_err(Clone::clone)?;
        let Some(parent) = parent_dir(path, false)? else {
            return Ok(None);
        };
        let name = cstring(path.file_name().ok_or(CacheError::Unavailable)?)?;
        let Some(file) = open_at(
            parent.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_NONBLOCK,
            false,
        )?
        else {
            return Ok(None);
        };
        let metadata = file.metadata().map_err(|_| CacheError::Unavailable)?;
        if !metadata.is_file() || metadata.len() > LIMIT as u64 {
            return Err(CacheError::Unavailable);
        }
        let mut bytes = Vec::new();
        file.take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| CacheError::Unavailable)?;
        if bytes.len() > LIMIT {
            return Err(CacheError::Unavailable);
        }
        let data: WireCache =
            serde_json::from_slice(&bytes).map_err(|_| CacheError::Unavailable)?;
        if data.version != 1 {
            return Err(CacheError::Unavailable);
        }
        Ok(Some(CachedTarget {
            boot_id: BootId(data.boot_id),
            os: match data.os {
                WireOs::Windows => Os::Windows,
                WireOs::Linux => Os::Linux,
            },
            description_utf16: data.description_utf16,
        }))
    }
    fn save(&self, target: &CachedTarget) -> Result<(), CacheError> {
        // Bound serialization before allocating a clone or touching the filesystem.
        if target
            .description_utf16
            .as_ref()
            .is_some_and(|s| s.len() > LIMIT / 6)
        {
            return Err(CacheError::Unavailable);
        }
        let data = WireCache {
            version: 1,
            boot_id: target.boot_id.0,
            os: match target.os {
                Os::Windows => WireOs::Windows,
                Os::Linux => WireOs::Linux,
            },
            description_utf16: target.description_utf16.clone(),
        };
        let bytes = serde_json::to_vec(&data).map_err(|_| CacheError::Unavailable)?;
        if bytes.len() > LIMIT {
            return Err(CacheError::Unavailable);
        }
        let path = self.path.as_ref().map_err(Clone::clone)?;
        write_atomic(path, &bytes)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let parent = parent_dir(path, true)?.ok_or(CacheError::Unavailable)?;
    let name = cstring(path.file_name().ok_or(CacheError::Unavailable)?)?;
    // Reject existing nonregular objects without following or blocking on them.
    if let Some(file) = open_at(
        parent.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_NONBLOCK,
        false,
    )? && !file
        .metadata()
        .map_err(|_| CacheError::Unavailable)?
        .is_file()
    {
        return Err(CacheError::Unavailable);
    }
    let temp = CString::new(format!(
        ".cache-v1-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| CacheError::Unavailable)?;
    let mut file = open_at(
        parent.as_raw_fd(),
        &temp,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        true,
    )?
    .ok_or(CacheError::Unavailable)?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| CacheError::Unavailable)?;
        file.sync_all().map_err(|_| CacheError::Unavailable)?;
        // renameat never follows a destination symlink. Pinned directory descriptors prevent ancestor races.
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                temp.as_ptr(),
                parent.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(CacheError::Unavailable);
        }
        parent.sync_all().map_err(|_| CacheError::Unavailable)
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), temp.as_ptr(), 0);
        }
    }
    result
}
fn cstring(value: &OsStr) -> Result<CString, CacheError> {
    CString::new(value.as_encoded_bytes()).map_err(|_| CacheError::Unavailable)
}
fn open_at(
    fd: i32,
    name: &CString,
    flags: i32,
    creating: bool,
) -> Result<Option<File>, CacheError> {
    // Owned File takes over exactly one successful descriptor. All opens reject symlinks.
    let opened = unsafe {
        libc::openat(
            fd,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if opened < 0 {
        if !creating && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(CacheError::Unavailable);
    }
    Ok(Some(unsafe { File::from_raw_fd(opened) }))
}
fn parent_dir(path: &Path, create: bool) -> Result<Option<File>, CacheError> {
    let root = CString::new("/").unwrap();
    let mut directory = open_at(
        libc::AT_FDCWD,
        &root,
        libc::O_RDONLY | libc::O_DIRECTORY,
        false,
    )?
    .ok_or(CacheError::Unavailable)?;
    for component in path.parent().ok_or(CacheError::Unavailable)?.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = cstring(name)?;
        let mut next = open_at(
            directory.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            false,
        )?;
        if next.is_none() && create {
            if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
            {
                return Err(CacheError::Unavailable);
            }
            next = open_at(
                directory.as_raw_fd(),
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                false,
            )?;
        }
        let Some(next) = next else {
            return Ok(None);
        };
        directory = next;
    }
    Ok(Some(directory))
}
