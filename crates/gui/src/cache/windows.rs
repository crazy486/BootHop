//! Untrusted per-user display cache for the Windows GUI.
//!
//! This cache is deliberately independent of the protected target store. It
//! contains only bounded display state and is never consulted to authorize a
//! Configure or Switch request.

use super::{Cache, CacheError, CachedTarget, sanitized_description};
use boothop_core::{BootId, Os};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const LIMIT: usize = 64 * 1024;
const CACHE_FILE: &str = "cache-v1.json";
const CACHE_DIRECTORY: &str = "BootHop";
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Resolve the one cache location beneath the LocalAppData known folder.
/// Tests pass an ordinary temporary absolute directory; production uses the
/// Windows known-folder API in `from_local_app_data`.
pub fn resolve_windows_cache_path(local_app_data: &OsStr) -> Result<PathBuf, CacheError> {
    let base = Path::new(local_app_data);
    validate_base(base)?;
    let path = base.join(CACHE_DIRECTORY).join(CACHE_FILE);
    validate_cache_path(&path)?;
    Ok(path)
}

pub struct WindowsCache {
    path: Result<PathBuf, CacheError>,
}

impl WindowsCache {
    pub fn at(path: PathBuf) -> Self {
        Self {
            path: validate_cache_path(&path).map(|_| path),
        }
    }

    /// Resolve LocalAppData through the system known-folder API. This native
    /// call is never used by tests, which use `resolve_windows_cache_path` or
    /// `at` with an ordinary temporary root.
    #[cfg(windows)]
    pub fn from_local_app_data() -> Self {
        Self {
            path: native_local_app_data_path(),
        }
    }
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
#[serde(deny_unknown_fields)]
enum WireOs {
    Windows,
    Linux,
}

impl Cache for WindowsCache {
    fn load(&self) -> Result<Option<CachedTarget>, CacheError> {
        let path = self.path.as_ref().map_err(Clone::clone)?;
        if has_reparse_component(path)? {
            return Err(CacheError::Unavailable);
        }
        let Some(_parent) = validate_parent(path, false)? else {
            return Ok(None);
        };
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CacheError::Unavailable),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > LIMIT as u64
        {
            return Err(CacheError::Unavailable);
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| CacheError::Unavailable)?
            .take((LIMIT + 1) as u64)
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
            description_utf16: data
                .description_utf16
                .map(|value| sanitized_description(&value)),
        }))
    }

    fn save(&self, target: &CachedTarget) -> Result<(), CacheError> {
        let path = self.path.as_ref().map_err(Clone::clone)?;
        validate_cache_path(path)?;
        if target
            .description_utf16
            .as_ref()
            .is_some_and(|value| value.len() > LIMIT / 6)
        {
            return Err(CacheError::Unavailable);
        }
        let description_utf16 = target
            .description_utf16
            .as_deref()
            .map(sanitized_description);
        let data = WireCache {
            version: 1,
            boot_id: target.boot_id.0,
            os: match target.os {
                Os::Windows => WireOs::Windows,
                Os::Linux => WireOs::Linux,
            },
            description_utf16,
        };
        let bytes = serde_json::to_vec(&data).map_err(|_| CacheError::Unavailable)?;
        if bytes.len() > LIMIT {
            return Err(CacheError::Unavailable);
        }
        let parent = validate_parent(path, true)?.ok_or(CacheError::Unavailable)?;
        if has_reparse_component(path)? {
            return Err(CacheError::Unavailable);
        }
        if let Ok(metadata) = fs::symlink_metadata(path)
            && (!metadata.is_file() || metadata.file_type().is_symlink())
        {
            return Err(CacheError::Unavailable);
        }
        let temp = parent.join(format!(
            ".cache-v1-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|_| CacheError::Unavailable)?;
        let result = (|| {
            file.write_all(&bytes)
                .map_err(|_| CacheError::Unavailable)?;
            file.sync_all().map_err(|_| CacheError::Unavailable)?;
            drop(file);
            atomic_replace(&temp, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

fn validate_base(base: &Path) -> Result<(), CacheError> {
    if !base.is_absolute()
        || base
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CacheError::Unavailable);
    }
    Ok(())
}

fn validate_cache_path(path: &Path) -> Result<(), CacheError> {
    if !path.is_absolute()
        || path.file_name() != Some(OsStr::new(CACHE_FILE))
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.parent().and_then(Path::file_name) != Some(OsStr::new(CACHE_DIRECTORY))
    {
        return Err(CacheError::Unavailable);
    }
    Ok(())
}

/// Validate every existing parent without following a symlink/reparse point.
/// If `create` is set, missing components are created one at a time and then
/// validated before the next component is reached.
fn validate_parent(path: &Path, create: bool) -> Result<Option<PathBuf>, CacheError> {
    let parent = path.parent().ok_or(CacheError::Unavailable)?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::Normal(name) => {
                current.push(name);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if !metadata.is_dir() || metadata.file_type().is_symlink() {
                            return Err(CacheError::Unavailable);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                        fs::create_dir(&current).map_err(|_| CacheError::Unavailable)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(None);
                    }
                    Err(_) => return Err(CacheError::Unavailable),
                }
            }
            Component::CurDir | Component::ParentDir => return Err(CacheError::Unavailable),
        }
        if has_reparse_component(&current)? {
            return Err(CacheError::Unavailable);
        }
    }
    Ok(Some(parent.to_path_buf()))
}

fn atomic_replace(from: &Path, to: &Path) -> Result<(), CacheError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let source: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(CacheError::Unavailable);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to).map_err(|_| CacheError::Unavailable)
    }
}

#[cfg(windows)]
fn has_reparse_component(path: &Path) -> Result<bool, CacheError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    };
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::Normal(name) => current.push(name),
            Component::CurDir | Component::ParentDir => return Err(CacheError::Unavailable),
        }
        let wide: Vec<u16> = current.as_os_str().encode_wide().chain(Some(0)).collect();
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(not(windows))]
fn has_reparse_component(path: &Path) -> Result<bool, CacheError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::Normal(name) => {
                current.push(name);
                if let Ok(metadata) = fs::symlink_metadata(&current) {
                    if metadata.file_type().is_symlink() {
                        return Ok(true);
                    }
                }
            }
            Component::Prefix(_) => current.push(component.as_os_str()),
            Component::CurDir | Component::ParentDir => return Err(CacheError::Unavailable),
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn native_local_app_data_path() -> Result<PathBuf, CacheError> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    };
    let mut raw_path = std::ptr::null_mut();
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            0,
            std::ptr::null_mut(),
            &mut raw_path,
        )
    };
    if hr < 0 || raw_path.is_null() {
        return Err(CacheError::Unavailable);
    }
    let mut len = 0;
    while unsafe { *raw_path.add(len) } != 0 {
        len += 1;
        if len > 32 * 1024 {
            unsafe { CoTaskMemFree(raw_path.cast()) };
            return Err(CacheError::Unavailable);
        }
    }
    let base = std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(raw_path, len) });
    unsafe { CoTaskMemFree(raw_path.cast()) };
    resolve_windows_cache_path(base.as_os_str())
}
