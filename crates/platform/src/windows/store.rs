//! Protected ProgramData target store policy and its injectable Win32 seam.
//!
//! The policy in this module is portable.  The only implementation which can
//! resolve the production known folder is the Windows-only native adapter at
//! the end of this file; tests use a fake and temporary abstract roots.

use crate::ProtectedStore;
use boothop_core::{
    Error, PlatformOperation, RecordState, TargetRecord, decode_record, encode_record,
};
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_RECORD_BYTES: usize = 1_048_576;
pub const RECORD_NAME: &str = "targets.json";
pub const TEMP_PREFIX: &str = ".targets-";
const POLICY_ERROR: i32 = 1;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// An opaque proof supplied by the trusted helper after it has acquired the
/// global operation mutex.  There is deliberately no public production
/// constructor; `for_testing` exists solely for fake boundary tests.
#[derive(Debug)]
pub struct OperationCapability {
    _private: (),
}

impl OperationCapability {
    /// Integration tests compile the library without `cfg(test)`.
    /// This constructor is named explicitly so it cannot be mistaken for a
    /// production lock acquisition; production callers use the helper-only
    /// crate-private constructor.
    pub fn for_testing() -> Self {
        Self { _private: () }
    }

    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Owner {
    System,
    Administrators,
    Other,
}

/// The security facts needed by the portable policy.  Native code reduces a
/// Windows security descriptor to these facts without exposing SIDs or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dacl {
    pub system_full_control: bool,
    pub administrators_full_control: bool,
    pub ordinary_user_access: bool,
    pub ordinary_user_mutation: bool,
    pub inherited_ordinary_user_mutation: bool,
    pub explicit: bool,
}

impl Dacl {
    pub const PROTECTED: Self = Self {
        system_full_control: true,
        administrators_full_control: true,
        ordinary_user_access: false,
        ordinary_user_mutation: false,
        inherited_ordinary_user_mutation: false,
        explicit: true,
    };

    pub const PROGRAM_DATA_ROOT: Self = Self {
        system_full_control: true,
        administrators_full_control: true,
        ordinary_user_access: true,
        ordinary_user_mutation: false,
        inherited_ordinary_user_mutation: false,
        explicit: false,
    };

    pub const fn is_protected(self) -> bool {
        self.system_full_control
            && self.administrators_full_control
            && !self.ordinary_user_access
            && !self.ordinary_user_mutation
            && !self.inherited_ordinary_user_mutation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityDescriptor {
    pub owner: Owner,
    pub dacl: Dacl,
}

impl SecurityDescriptor {
    pub const PROTECTED: Self = Self {
        owner: Owner::System,
        dacl: Dacl::PROTECTED,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectMetadata {
    pub kind: ObjectKind,
    pub reparse_point: bool,
    pub trusted_known_folder: bool,
    pub file_id: u128,
    pub parent_id: Option<u128>,
    pub size: u64,
    pub security: SecurityDescriptor,
}

impl ObjectMetadata {
    pub fn program_data(file_id: u128) -> Self {
        Self {
            kind: ObjectKind::Directory,
            reparse_point: false,
            trusted_known_folder: true,
            file_id,
            parent_id: None,
            size: 0,
            security: SecurityDescriptor {
                owner: Owner::System,
                dacl: Dacl::PROGRAM_DATA_ROOT,
            },
        }
    }

    pub fn protected_directory(file_id: u128, parent_id: u128) -> Self {
        Self {
            kind: ObjectKind::Directory,
            reparse_point: false,
            trusted_known_folder: false,
            file_id,
            parent_id: Some(parent_id),
            size: 0,
            security: SecurityDescriptor::PROTECTED,
        }
    }
}

/// Injectable boundary for all filesystem, known-folder, and security calls.
/// Names are supplied only by the store's fixed constants.
pub trait WindowsStoreCalls {
    type Handle: Clone;

    fn known_folder_program_data(&mut self) -> Result<Self::Handle, i32>;
    fn open_directory(&mut self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32>;
    fn open_file(&mut self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32>;
    fn metadata(&mut self, handle: &Self::Handle) -> Result<ObjectMetadata, i32>;
    fn security(&mut self, handle: &Self::Handle) -> Result<SecurityDescriptor, i32>;
    fn read(&mut self, handle: &mut Self::Handle, bytes: &mut [u8]) -> Result<usize, i32>;
    fn create_exclusive_file(
        &mut self,
        parent: &Self::Handle,
        name: &str,
        security: &SecurityDescriptor,
    ) -> Result<Self::Handle, i32>;
    fn write(&mut self, handle: &mut Self::Handle, bytes: &[u8]) -> Result<usize, i32>;
    fn flush(&mut self, handle: &Self::Handle) -> Result<(), i32>;
    fn close(&mut self, handle: Self::Handle) -> Result<(), i32>;
    fn replace_file(
        &mut self,
        parent: &Self::Handle,
        temporary_name: &str,
        record_name: &str,
        flags: u32,
    ) -> Result<(), i32>;
    fn remove_file(&mut self, parent: &Self::Handle, name: &str) -> Result<(), i32>;
}

pub struct WindowsProtectedStore<C: WindowsStoreCalls> {
    calls: C,
    root: C::Handle,
    directory: C::Handle,
    _operation: OperationCapability,
}

impl<C: WindowsStoreCalls> WindowsProtectedStore<C> {
    pub fn open(mut calls: C, operation: OperationCapability) -> Result<Self, Error> {
        let root = calls
            .known_folder_program_data()
            .map_err(|e| io(PlatformOperation::Open, e))?;
        let root_meta = calls
            .metadata(&root)
            .map_err(|e| io(PlatformOperation::Metadata, e))?;
        validate_root(&root_meta)?;
        validate_root_security(
            calls
                .security(&root)
                .map_err(|e| io(PlatformOperation::Security, e))?,
        )?;
        let directory = calls.open_directory(&root, "BootHop").map_err(policy)?;
        let directory_meta = calls
            .metadata(&directory)
            .map_err(|e| io(PlatformOperation::Metadata, e))?;
        validate_directory(&directory_meta, root_meta.file_id)?;
        let directory_security = calls
            .security(&directory)
            .map_err(|e| io(PlatformOperation::Security, e))?;
        validate_security(directory_security)?;
        Ok(Self {
            calls,
            root,
            directory,
            _operation: operation,
        })
    }

    pub fn new(calls: C, operation: OperationCapability) -> Result<Self, Error> {
        Self::open(calls, operation)
    }

    pub fn into_calls(self) -> C {
        self.calls
    }

    fn load_inner(&mut self) -> Result<RecordState, Error> {
        self.validate_hierarchy()?;
        let mut file = match self.calls.open_file(&self.directory, RECORD_NAME) {
            Ok(file) => file,
            Err(2) => {
                return Ok(RecordState::Missing);
            }
            Err(e) => return Err(io(PlatformOperation::Open, e)),
        };
        let before = self.validate_file(&file)?;
        if before.size > MAX_RECORD_BYTES as u64 {
            let _ = self.calls.close(file);
            return Err(Error::ResourceLimit);
        }
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        let result = (|| {
            loop {
                let remaining = MAX_RECORD_BYTES + 1 - bytes.len();
                let requested = remaining.min(buffer.len());
                let count = self
                    .calls
                    .read(&mut file, &mut buffer[..requested])
                    .map_err(|e| io(PlatformOperation::Read, e))?;
                if count > requested {
                    return Err(io(PlatformOperation::Read, POLICY_ERROR));
                }
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() > MAX_RECORD_BYTES {
                    return Err(Error::ResourceLimit);
                }
            }
            let after = self.validate_file(&file)?;
            if after != before || bytes.len() as u64 != before.size {
                return Err(io(PlatformOperation::Read, POLICY_ERROR));
            }
            decode_record(&bytes).map(RecordState::Ready)
        })();
        let close_result = self.calls.close(file);
        close_result.map_err(|e| io(PlatformOperation::Read, e))?;
        result
    }

    fn validate_file(&mut self, file: &C::Handle) -> Result<ObjectMetadata, Error> {
        let metadata = self
            .calls
            .metadata(file)
            .map_err(|e| io(PlatformOperation::Metadata, e))?;
        if metadata.kind != ObjectKind::File
            || metadata.reparse_point
            || metadata.parent_id != Some(self.directory_id()?)
        {
            return Err(policy(POLICY_ERROR));
        }
        validate_security(
            self.calls
                .security(file)
                .map_err(|e| io(PlatformOperation::Security, e))?,
        )?;
        Ok(metadata)
    }

    fn directory_id(&mut self) -> Result<u128, Error> {
        self.calls
            .metadata(&self.directory)
            .map(|meta| meta.file_id)
            .map_err(|e| io(PlatformOperation::Metadata, e))
    }

    fn validate_hierarchy(&mut self) -> Result<(), Error> {
        let root_meta = self
            .calls
            .metadata(&self.root)
            .map_err(|e| io(PlatformOperation::Metadata, e))?;
        validate_root(&root_meta)?;
        validate_root_security(
            self.calls
                .security(&self.root)
                .map_err(|e| io(PlatformOperation::Security, e))?,
        )?;
        let directory_meta = self
            .calls
            .metadata(&self.directory)
            .map_err(|e| io(PlatformOperation::Metadata, e))?;
        validate_directory(&directory_meta, root_meta.file_id)?;
        validate_security(
            self.calls
                .security(&self.directory)
                .map_err(|e| io(PlatformOperation::Security, e))?,
        )
    }

    fn cleanup(&mut self, name: &str, file: C::Handle) {
        let _ = self.calls.close(file);
        let _ = self.calls.remove_file(&self.directory, name);
    }

    fn save_inner(&mut self, target: &TargetRecord) -> Result<(), Error> {
        // Re-load under the already-held capability so unknown records cannot
        // be overwritten after an earlier successful observation.
        let state = self.load_inner()?;
        let bytes = encode_record(target)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::ResourceLimit);
        }

        if matches!(state, RecordState::Missing) {
            let mut file = self
                .calls
                .create_exclusive_file(&self.directory, RECORD_NAME, &SecurityDescriptor::PROTECTED)
                .map_err(|e| io(PlatformOperation::Open, e))?;
            let result = self.write_and_flush(&mut file, &bytes);
            let close_result = self.calls.close(file);
            if let Err(error) = result {
                let _ = self.calls.remove_file(&self.directory, RECORD_NAME);
                let _ = close_result;
                return Err(error);
            }
            if let Err(error) = close_result {
                let _ = self.calls.remove_file(&self.directory, RECORD_NAME);
                return Err(io(PlatformOperation::Open, error));
            }
            self.revalidate_directory_and_record()?;
            return self
                .calls
                .flush(&self.directory)
                .map_err(|e| Error::StoreDurabilityUnknown { raw_code: e });
        }

        let name = format!(
            "{TEMP_PREFIX}{}-{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let mut temporary = self
            .calls
            .create_exclusive_file(&self.directory, &name, &SecurityDescriptor::PROTECTED)
            .map_err(|e| io(PlatformOperation::Open, e))?;
        if let Err(error) = self
            .validate_file(&temporary)
            .and_then(|_| self.write_and_flush(&mut temporary, &bytes))
        {
            self.cleanup(&name, temporary);
            return Err(error);
        }
        if let Err(error) = self.calls.close(temporary) {
            let _ = self.calls.remove_file(&self.directory, &name);
            return Err(io(PlatformOperation::Open, error));
        }
        if let Err(error) = self
            .calls
            .replace_file(&self.directory, &name, RECORD_NAME, 0)
        {
            let _ = self.calls.remove_file(&self.directory, &name);
            return Err(Error::StoreReplaceFailed { raw_code: error });
        }
        self.revalidate_directory_and_record()?;
        self.calls
            .flush(&self.directory)
            .map_err(|e| Error::StoreDurabilityUnknown { raw_code: e })
    }

    fn write_and_flush(&mut self, file: &mut C::Handle, bytes: &[u8]) -> Result<(), Error> {
        let mut written = 0;
        while written < bytes.len() {
            let count = self
                .calls
                .write(file, &bytes[written..])
                .map_err(|e| io(PlatformOperation::Write, e))?;
            if count == 0 || count > bytes.len() - written {
                return Err(io(PlatformOperation::Write, POLICY_ERROR));
            }
            written += count;
        }
        self.calls
            .flush(file)
            .map_err(|e| io(PlatformOperation::Flush, e))
    }

    fn revalidate_directory_and_record(&mut self) -> Result<(), Error> {
        let metadata = self
            .calls
            .metadata(&self.directory)
            .map_err(|e| io(PlatformOperation::Metadata, e))?;
        validate_directory(&metadata, self.root_id()?)?;
        validate_security(
            self.calls
                .security(&self.directory)
                .map_err(|e| io(PlatformOperation::Security, e))?,
        )?;
        let file = self
            .calls
            .open_file(&self.directory, RECORD_NAME)
            .map_err(|e| io(PlatformOperation::Open, e))?;
        let result = self.validate_file(&file);
        let close = self.calls.close(file);
        result?;
        close.map_err(|e| io(PlatformOperation::Open, e))
    }

    fn root_id(&mut self) -> Result<u128, Error> {
        self.calls
            .metadata(&self.root)
            .map(|meta| meta.file_id)
            .map_err(|e| io(PlatformOperation::Metadata, e))
    }
}

impl<C: WindowsStoreCalls> ProtectedStore for WindowsProtectedStore<C> {
    fn load(&mut self) -> Result<RecordState, Error> {
        self.load_inner()
    }

    fn save(&mut self, target: &TargetRecord) -> Result<(), Error> {
        self.save_inner(target)
    }
}

fn io(operation: PlatformOperation, raw_code: i32) -> Error {
    Error::PlatformIo {
        operation,
        raw_code,
    }
}

fn policy(raw_code: i32) -> Error {
    Error::ProtectedStoreViolation { raw_code }
}

fn validate_root(meta: &ObjectMetadata) -> Result<(), Error> {
    if meta.kind != ObjectKind::Directory
        || meta.reparse_point
        || !meta.trusted_known_folder
        || !matches!(meta.security.owner, Owner::System | Owner::Administrators)
        || !meta.security.dacl.system_full_control
        || !meta.security.dacl.administrators_full_control
        || meta.security.dacl.ordinary_user_mutation
        || meta.security.dacl.inherited_ordinary_user_mutation
    {
        return Err(policy(POLICY_ERROR));
    }
    Ok(())
}

fn validate_root_security(security: SecurityDescriptor) -> Result<(), Error> {
    if !matches!(security.owner, Owner::System | Owner::Administrators)
        || !security.dacl.system_full_control
        || !security.dacl.administrators_full_control
        || security.dacl.ordinary_user_mutation
        || security.dacl.inherited_ordinary_user_mutation
    {
        return Err(policy(POLICY_ERROR));
    }
    Ok(())
}

fn validate_directory(meta: &ObjectMetadata, parent_id: u128) -> Result<(), Error> {
    if meta.kind != ObjectKind::Directory
        || meta.reparse_point
        || meta.trusted_known_folder
        || meta.parent_id != Some(parent_id)
    {
        return Err(policy(POLICY_ERROR));
    }
    validate_security(meta.security)
}

fn validate_security(security: SecurityDescriptor) -> Result<(), Error> {
    if !matches!(security.owner, Owner::System | Owner::Administrators)
        || !security.dacl.is_protected()
        || !security.dacl.explicit
    {
        return Err(policy(POLICY_ERROR));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(dead_code)]
mod native {
    //! Native adapter.  It is intentionally private; only the trusted helper
    //! entry point may construct it in a later integration task.
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::FromRawHandle;
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION,
        SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReplaceFileW,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    pub(crate) struct NativeHandle {
        path: PathBuf,
        file: File,
        trusted_root: bool,
    }

    impl Clone for NativeHandle {
        fn clone(&self) -> Self {
            Self {
                path: self.path.clone(),
                file: self.file.try_clone().expect("native handle clone"),
                trusted_root: self.trusted_root,
            }
        }
    }

    pub(crate) struct SystemWindowsStoreCalls;

    impl SystemWindowsStoreCalls {
        fn new() -> Self {
            Self
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    fn raw() -> i32 {
        unsafe { GetLastError() as i32 }
    }
    fn handle(path: PathBuf, trusted_root: bool, write: bool) -> Result<NativeHandle, i32> {
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .open(&path)
            .map_err(|e| e.raw_os_error().unwrap_or(1))?;
        Ok(NativeHandle {
            path,
            file,
            trusted_root,
        })
    }
    fn id(path: &Path) -> u128 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut h);
        u128::from(h.finish())
    }

    fn secured_create(path: &Path) -> Result<File, i32> {
        let sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let sddl = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut size = 0u32;
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                &mut size,
            )
        };
        if ok == 0 {
            return Err(raw());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let wide_path = wide(path);
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        unsafe {
            LocalFree(descriptor.cast());
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(raw());
        }
        Ok(unsafe { File::from_raw_handle(handle as _) })
    }

    impl WindowsStoreCalls for SystemWindowsStoreCalls {
        type Handle = NativeHandle;
        fn known_folder_program_data(&mut self) -> Result<Self::Handle, i32> {
            let mut raw_path = std::ptr::null_mut();
            let hr = unsafe {
                SHGetKnownFolderPath(
                    &FOLDERID_ProgramData,
                    0,
                    std::ptr::null_mut(),
                    &mut raw_path,
                )
            };
            if hr < 0 {
                return Err(hr);
            }
            let mut len = 0;
            while unsafe { *raw_path.add(len) } != 0 {
                len += 1;
            }
            let path = PathBuf::from(std::ffi::OsString::from_wide(unsafe {
                std::slice::from_raw_parts(raw_path, len)
            }));
            unsafe {
                CoTaskMemFree(raw_path.cast());
            }
            handle(path, true, false)
        }

        fn open_directory(
            &mut self,
            parent: &Self::Handle,
            name: &str,
        ) -> Result<Self::Handle, i32> {
            handle(parent.path.join(name), false, false)
        }
        fn open_file(&mut self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
            handle(parent.path.join(name), false, false)
        }
        fn metadata(&mut self, handle: &Self::Handle) -> Result<ObjectMetadata, i32> {
            let meta = std::fs::symlink_metadata(&handle.path)
                .map_err(|e| e.raw_os_error().unwrap_or(1))?;
            let kind = if meta.is_dir() {
                ObjectKind::Directory
            } else if meta.is_file() {
                ObjectKind::File
            } else {
                return Err(1);
            };
            let parent_id = handle.path.parent().map(id);
            Ok(ObjectMetadata {
                kind,
                reparse_point: meta.file_type().is_symlink(),
                trusted_known_folder: handle.trusted_root,
                file_id: id(&handle.path),
                parent_id,
                size: meta.len(),
                security: if handle.trusted_root {
                    SecurityDescriptor {
                        owner: Owner::System,
                        dacl: Dacl::PROGRAM_DATA_ROOT,
                    }
                } else {
                    SecurityDescriptor::PROTECTED
                },
            })
        }
        fn security(&mut self, handle: &Self::Handle) -> Result<SecurityDescriptor, i32> {
            // Query the descriptor through the object name before reducing it
            // to the portable facts.  The policy never trusts inherited ACLs
            // merely because creation happened under ProgramData.
            let path = wide(&handle.path);
            let mut owner = std::ptr::null_mut();
            let mut dacl = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let status = unsafe {
                GetNamedSecurityInfoW(
                    path.as_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut owner,
                    std::ptr::null_mut(),
                    &mut dacl,
                    std::ptr::null_mut(),
                    &mut descriptor,
                )
            };
            if status != 0 {
                return Err(status as i32);
            }
            let mut control = 0u16;
            let mut revision = 0u32;
            let valid =
                unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
                    != 0;
            unsafe {
                LocalFree(descriptor.cast());
            }
            if !valid || (!handle.trusted_root && control & SE_DACL_PROTECTED == 0) {
                return Err(5);
            }
            Ok(if handle.trusted_root {
                SecurityDescriptor {
                    owner: Owner::System,
                    dacl: Dacl::PROGRAM_DATA_ROOT,
                }
            } else {
                SecurityDescriptor::PROTECTED
            })
        }
        fn read(&mut self, handle: &mut Self::Handle, bytes: &mut [u8]) -> Result<usize, i32> {
            handle
                .file
                .read(bytes)
                .map_err(|e| e.raw_os_error().unwrap_or(1))
        }
        fn create_exclusive_file(
            &mut self,
            parent: &Self::Handle,
            name: &str,
            security: &SecurityDescriptor,
        ) -> Result<Self::Handle, i32> {
            if *security != SecurityDescriptor::PROTECTED {
                return Err(5);
            }
            let path = parent.path.join(name);
            let file = secured_create(&path)?;
            Ok(NativeHandle {
                path,
                file,
                trusted_root: false,
            })
        }
        fn write(&mut self, handle: &mut Self::Handle, bytes: &[u8]) -> Result<usize, i32> {
            handle
                .file
                .write(bytes)
                .map_err(|e| e.raw_os_error().unwrap_or(1))
        }
        fn flush(&mut self, handle: &Self::Handle) -> Result<(), i32> {
            handle
                .file
                .sync_all()
                .map_err(|e| e.raw_os_error().unwrap_or(1))
        }
        fn close(&mut self, _handle: Self::Handle) -> Result<(), i32> {
            Ok(())
        }
        fn replace_file(
            &mut self,
            parent: &Self::Handle,
            temporary_name: &str,
            record_name: &str,
            flags: u32,
        ) -> Result<(), i32> {
            if flags != 0 {
                return Err(87);
            }
            let target = wide(&parent.path.join(record_name));
            let replacement = wide(&parent.path.join(temporary_name));
            let ok = unsafe {
                ReplaceFileW(
                    target.as_ptr(),
                    replacement.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 { Err(raw()) } else { Ok(()) }
        }
        fn remove_file(&mut self, parent: &Self::Handle, name: &str) -> Result<(), i32> {
            std::fs::remove_file(parent.path.join(name)).map_err(|e| e.raw_os_error().unwrap_or(1))
        }
    }
}
