//! Untrusted per-user display cache for the Windows GUI.
//!
//! This cache is deliberately independent of the protected target store. It
//! contains only bounded display state and is never consulted to authorize a
//! Configure or Switch request.

use super::{Cache, CacheError, CachedTarget, sanitized_description};
use boothop_core::{BootId, Os};
use serde::{Deserialize, Serialize};
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::{
    ffi::OsStr,
    fs::{self, File},
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
        #[cfg(windows)]
        return load_native(path);
        #[cfg(not(windows))]
        load_portable(path)
    }

    fn save(&self, target: &CachedTarget) -> Result<(), CacheError> {
        let path = self.path.as_ref().map_err(Clone::clone)?;
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
        #[cfg(windows)]
        return save_native(path, &bytes);
        #[cfg(not(windows))]
        save_portable(path, &bytes)
    }
}

#[cfg(not(windows))]
fn load_portable(path: &Path) -> Result<Option<CachedTarget>, CacheError> {
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
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > LIMIT as u64 {
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
    let data: WireCache = serde_json::from_slice(&bytes).map_err(|_| CacheError::Unavailable)?;
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

#[cfg(not(windows))]
fn save_portable(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    validate_cache_path(path)?;
    let parent = validate_parent(path, true)?.ok_or(CacheError::Unavailable)?;
    if has_reparse_component(path)? {
        return Err(CacheError::Unavailable);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(CacheError::Unavailable);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(CacheError::Unavailable),
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
        file.write_all(bytes).map_err(|_| CacheError::Unavailable)?;
        file.sync_all().map_err(|_| CacheError::Unavailable)
    })();
    drop(file);
    let result = result.and_then(|()| atomic_replace(&temp, path));
    if result.is_err() {
        if fs::remove_file(&temp).is_err() {
            return Err(CacheError::Unavailable);
        }
    }
    result
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    volume: u32,
    index: u64,
}

#[cfg(windows)]
struct NativeDirectory {
    _file: File,
    identity: ObjectIdentity,
    final_path: PathBuf,
}

#[cfg(windows)]
struct NativeFile {
    file: File,
    identity: ObjectIdentity,
    final_path: PathBuf,
}

#[cfg(windows)]
struct NativeContext {
    _root: NativeDirectory,
    parent: NativeDirectory,
}

#[cfg(windows)]
type NativeOpenResult = (File, ObjectIdentity, PathBuf, bool, bool);

#[cfg(windows)]
fn load_native(path: &Path) -> Result<Option<CachedTarget>, CacheError> {
    let Some(context) = native_context(path, false)? else {
        return Ok(None);
    };
    let Some(cache_file) = native_open_file(path, false)? else {
        return Ok(None);
    };
    validate_context(&context)?;
    validate_child_file(&context.parent, &cache_file, path)?;
    if cache_file_size(&cache_file)? > LIMIT as u64 {
        return Err(CacheError::Unavailable);
    }
    let mut bytes = Vec::new();
    cache_file
        .file
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CacheError::Unavailable)?;
    if bytes.len() > LIMIT {
        return Err(CacheError::Unavailable);
    }
    let Some(current_file) = native_open_file(path, false)? else {
        return Err(CacheError::Unavailable);
    };
    validate_child_file(&context.parent, &current_file, path)?;
    if current_file.identity != cache_file.identity {
        return Err(CacheError::Unavailable);
    }
    let data: WireCache = serde_json::from_slice(&bytes).map_err(|_| CacheError::Unavailable)?;
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

#[cfg(windows)]
fn save_native(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    validate_cache_path(path)?;
    let context = native_context(path, true)?.ok_or(CacheError::Unavailable)?;
    validate_context(&context)?;
    if let Some(cache_file) = native_open_file(path, false)? {
        validate_child_file(&context.parent, &cache_file, path)?;
    }
    let temp = context.parent.final_path.join(format!(
        ".cache-v1-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut temp_file = match native_open_file_at(&temp, true) {
        Ok(file) => file,
        Err(error) => {
            if fs::remove_file(&temp).is_err() {
                return Err(CacheError::Unavailable);
            }
            return Err(error);
        }
    };
    if let Err(error) = validate_child_file(&context.parent, &temp_file, &temp) {
        drop(temp_file);
        if fs::remove_file(&temp).is_err() {
            return Err(CacheError::Unavailable);
        }
        return Err(error);
    }
    let result = (|| {
        temp_file
            .file
            .write_all(bytes)
            .map_err(|_| CacheError::Unavailable)?;
        temp_file
            .file
            .sync_all()
            .map_err(|_| CacheError::Unavailable)
    })();
    drop(temp_file);
    let result = result
        .and_then(|()| validate_context(&context))
        .and_then(|()| atomic_replace(&temp, path));
    if result.is_err() {
        if fs::remove_file(&temp).is_err() {
            return Err(CacheError::Unavailable);
        }
        return result;
    }
    validate_context(&context)?;
    let Some(cache_file) = native_open_file(path, false)? else {
        return Err(CacheError::Unavailable);
    };
    validate_child_file(&context.parent, &cache_file, path)
}

#[cfg(windows)]
fn native_context(path: &Path, create_parent: bool) -> Result<Option<NativeContext>, CacheError> {
    let root_path = path
        .parent()
        .and_then(Path::parent)
        .ok_or(CacheError::Unavailable)?;
    let Some(root) = native_open_directory(root_path, false)? else {
        return Ok(None);
    };
    validate_directory(&root, None, root_path)?;
    let parent_path = root_path.join(CACHE_DIRECTORY);
    let parent = match native_open_directory(&parent_path, false)? {
        Some(parent) => parent,
        None if create_parent => {
            native_create_directory(&parent_path)?;
            native_open_directory(&parent_path, false)?.ok_or(CacheError::Unavailable)?
        }
        None => return Ok(None),
    };
    validate_directory(&parent, Some(&root), &parent_path)?;
    Ok(Some(NativeContext {
        _root: root,
        parent,
    }))
}

#[cfg(windows)]
fn native_create_directory(path: &Path) -> Result<(), CacheError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { CreateDirectoryW(wide.as_ptr(), std::ptr::null()) } == 0 {
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if error != 183 {
            return Err(CacheError::Unavailable);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn native_open_directory(
    path: &Path,
    _create: bool,
) -> Result<Option<NativeDirectory>, CacheError> {
    let Some((file, identity, final_path, is_directory, reparse)) = native_open(path, false, true)?
    else {
        return Ok(None);
    };
    if !is_directory || reparse {
        return Err(CacheError::Unavailable);
    }
    Ok(Some(NativeDirectory {
        _file: file,
        identity,
        final_path,
    }))
}

#[cfg(windows)]
fn native_open_file(path: &Path, create_new: bool) -> Result<Option<NativeFile>, CacheError> {
    let Some((file, identity, final_path, is_directory, reparse)) =
        native_open(path, create_new, false)?
    else {
        return Ok(None);
    };
    if is_directory || reparse {
        return Err(CacheError::Unavailable);
    }
    Ok(Some(NativeFile {
        file,
        identity,
        final_path,
    }))
}

#[cfg(windows)]
fn native_open_file_at(path: &Path, create_new: bool) -> Result<NativeFile, CacheError> {
    native_open_file(path, create_new)?.ok_or(CacheError::Unavailable)
}

#[cfg(windows)]
fn native_open(
    path: &Path,
    create_new: bool,
    directory: bool,
) -> Result<Option<NativeOpenResult>, CacheError> {
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    use windows_sys::Win32::{
        Foundation::{GetLastError, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING,
        },
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let disposition = if create_new {
        windows_sys::Win32::Storage::FileSystem::CREATE_NEW
    } else {
        OPEN_EXISTING
    };
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | if create_new { FILE_GENERIC_WRITE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            disposition,
            flags,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        if !create_new && (error == 2 || error == 3) {
            return Ok(None);
        }
        return Err(CacheError::Unavailable);
    }
    let file = unsafe { File::from_raw_handle(raw as _) };
    let identity = native_identity(&file)?;
    let (is_directory, reparse) = native_type(&file)?;
    let final_path = native_final_path(&file)?;
    Ok(Some((file, identity, final_path, is_directory, reparse)))
}

#[cfg(windows)]
fn native_identity(file: &File) -> Result<ObjectIdentity, CacheError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
        return Err(CacheError::Unavailable);
    }
    Ok(ObjectIdentity {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

#[cfg(windows)]
fn native_type(file: &File) -> Result<(bool, bool), CacheError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_STANDARD_INFO,
        FileAttributeTagInfo, FileStandardInfo, GetFileInformationByHandleEx,
    };
    let mut tags = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as _,
            FileAttributeTagInfo,
            (&mut tags as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(CacheError::Unavailable);
    }
    let mut standard = FILE_STANDARD_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as _,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(CacheError::Unavailable);
    }
    Ok((
        standard.Directory,
        tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || tags.ReparseTag != 0,
    ))
}

#[cfg(windows)]
fn native_final_path(file: &File) -> Result<PathBuf, CacheError> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };
    let mut buffer = vec![0u16; 512];
    loop {
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle() as _,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if length == 0 {
            return Err(CacheError::Unavailable);
        }
        if (length as usize) < buffer.len() {
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(
                &buffer[..length as usize],
            )));
        }
        if length as usize >= 32 * 1024 {
            return Err(CacheError::Unavailable);
        }
        buffer.resize(length as usize + 1, 0);
    }
}

#[cfg(windows)]
fn cache_file_size(file: &NativeFile) -> Result<u64, CacheError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };
    let mut standard = FILE_STANDARD_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.file.as_raw_handle() as _,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
        || standard.EndOfFile < 0
    {
        return Err(CacheError::Unavailable);
    }
    Ok(standard.EndOfFile as u64)
}

#[cfg(windows)]
fn validate_directory(
    directory: &NativeDirectory,
    parent: Option<&NativeDirectory>,
    expected: &Path,
) -> Result<(), CacheError> {
    if let Some(parent) = parent {
        if !same_path(
            directory
                .final_path
                .parent()
                .ok_or(CacheError::Unavailable)?,
            &parent.final_path,
        ) {
            return Err(CacheError::Unavailable);
        }
    } else if !same_path(&directory.final_path, expected) {
        return Err(CacheError::Unavailable);
    }
    if directory.identity.volume == 0 || directory.identity.index == 0 {
        return Err(CacheError::Unavailable);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_child_file(
    parent: &NativeDirectory,
    file: &NativeFile,
    expected: &Path,
) -> Result<(), CacheError> {
    if !child_facts_valid(
        &parent.final_path,
        parent.identity,
        &file.final_path,
        file.identity,
        expected,
        true,
        false,
    ) {
        return Err(CacheError::Unavailable);
    }
    Ok(())
}

#[cfg(windows)]
fn child_facts_valid(
    parent_path: &Path,
    parent_identity: ObjectIdentity,
    child_path: &Path,
    child_identity: ObjectIdentity,
    expected: &Path,
    regular_file: bool,
    reparse: bool,
) -> bool {
    child_path
        .parent()
        .is_some_and(|path| same_path(path, parent_path))
        && same_path(child_path, expected)
        && regular_file
        && !reparse
        && parent_identity.volume != 0
        && parent_identity.index != 0
        && child_identity.volume != 0
        && child_identity.index != 0
}

#[cfg(windows)]
fn validate_context(context: &NativeContext) -> Result<(), CacheError> {
    let current_root =
        native_open_directory(&context._root.final_path, false)?.ok_or(CacheError::Unavailable)?;
    if !identity_unchanged(context._root.identity, current_root.identity)
        || !same_path(&current_root.final_path, &context._root.final_path)
    {
        return Err(CacheError::Unavailable);
    }
    let current_parent =
        native_open_directory(&context.parent.final_path, false)?.ok_or(CacheError::Unavailable)?;
    if !identity_unchanged(context.parent.identity, current_parent.identity)
        || !same_path(&current_parent.final_path, &context.parent.final_path)
    {
        return Err(CacheError::Unavailable);
    }
    Ok(())
}

#[cfg(windows)]
fn identity_unchanged(expected: ObjectIdentity, current: ObjectIdentity) -> bool {
    expected == current && expected.volume != 0 && expected.index != 0
}

#[cfg(windows)]
fn same_path(left: &Path, right: &Path) -> bool {
    normalize_final_path(left) == normalize_final_path(right)
}

#[cfg(windows)]
fn normalize_final_path(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('/', "\\");
    if let Some(stripped) = value.strip_prefix(r"\\?\") {
        value = stripped.to_owned();
    }
    while value.ends_with('\\') && value.len() > 3 {
        value.pop();
    }
    value.to_ascii_lowercase()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn id(value: u64) -> ObjectIdentity {
        ObjectIdentity {
            volume: 1,
            index: value,
        }
    }

    #[test]
    fn fake_junction_swap_and_final_path_escape_are_rejected() {
        let parent = Path::new(r"C:\Users\test\AppData\Local\BootHop");
        let expected = parent.join(CACHE_FILE);
        assert!(child_facts_valid(
            parent,
            id(1),
            &expected,
            id(2),
            &expected,
            true,
            false,
        ));
        assert!(!child_facts_valid(
            parent,
            id(1),
            Path::new(r"C:\Users\test\AppData\Local\Other\cache-v1.json"),
            id(2),
            &expected,
            true,
            false,
        ));
    }

    #[test]
    fn fake_object_type_and_parent_identity_change_fail_closed() {
        let parent = Path::new(r"C:\Users\test\AppData\Local\BootHop");
        let expected = parent.join(CACHE_FILE);
        assert!(!child_facts_valid(
            parent,
            id(1),
            &expected,
            id(2),
            &expected,
            false,
            false,
        ));
        assert!(!identity_unchanged(id(1), id(9)));
        assert!(!child_facts_valid(
            parent,
            id(1),
            &expected,
            id(2),
            &expected,
            true,
            true,
        ));
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
#[cfg(not(windows))]
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

#[cfg(not(windows))]
fn has_reparse_component(path: &Path) -> Result<bool, CacheError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::Normal(name) => {
                current.push(name);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(CacheError::Unavailable),
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
    if hr < 0 {
        if !raw_path.is_null() {
            unsafe { CoTaskMemFree(raw_path.cast()) };
        }
        return Err(CacheError::Unavailable);
    }
    if raw_path.is_null() {
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
