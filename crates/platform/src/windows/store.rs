//! Protected ProgramData target store policy and its injectable Win32 seam.
#![allow(dead_code)]
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
pub(crate) struct OperationCapability {
    _private: (),
}

impl OperationCapability {
    /// Integration tests compile the library without `cfg(test)`.
    /// This constructor is named explicitly so it cannot be mistaken for a
    /// production lock acquisition; production callers use the helper-only
    /// crate-private constructor.
    #[cfg(test)]
    fn for_testing() -> Self {
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

pub(crate) struct WindowsProtectedStore<C: WindowsStoreCalls> {
    calls: C,
    root: C::Handle,
    directory: C::Handle,
    _operation: OperationCapability,
}

impl<C: WindowsStoreCalls> WindowsProtectedStore<C> {
    pub(crate) fn open(mut calls: C, operation: OperationCapability) -> Result<Self, Error> {
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

    pub(crate) fn new(calls: C, operation: OperationCapability) -> Result<Self, Error> {
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
            self.calls
                .close(file)
                .map_err(|e| io(PlatformOperation::Read, e))?;
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

    fn cleanup(&mut self, name: &str, file: C::Handle) -> Result<(), Error> {
        let close = self.calls.close(file);
        let remove = self.calls.remove_file(&self.directory, name);
        if let Err(raw_code) = close {
            return Err(io(PlatformOperation::Open, raw_code));
        }
        remove.map_err(|raw_code| io(PlatformOperation::Open, raw_code))
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
                // The exclusive final was already created. Preserve it for
                // administrator inspection; it may contain the only durable
                // copy after an uncertain native failure.
                return match close_result {
                    Ok(()) => Err(error),
                    Err(close_error) => Err(io(PlatformOperation::Open, close_error)),
                };
            }
            if let Err(error) = close_result {
                return Err(io(PlatformOperation::Open, error));
            }
            if let Err(_error) = self.revalidate_directory_and_record() {
                return Err(Error::StoreDurabilityUnknown {
                    raw_code: POLICY_ERROR,
                });
            }
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
            return Err(self.cleanup(&name, temporary).err().unwrap_or(error));
        }
        if let Err(error) = self.calls.close(temporary) {
            let cleanup = self.calls.remove_file(&self.directory, &name);
            return Err(cleanup
                .map_err(|raw_code| io(PlatformOperation::Open, raw_code))
                .err()
                .unwrap_or_else(|| io(PlatformOperation::Open, error)));
        }
        if let Err(error) = self
            .calls
            .replace_file(&self.directory, &name, RECORD_NAME, 0)
        {
            // ReplaceFileW may have completed the rename before reporting a
            // failure. Never delete the replacement in this state and never
            // retry; the artifact is part of the durability-unknown outcome.
            return Err(Error::StoreDurabilityUnknown { raw_code: error });
        }
        if let Err(_error) = self.revalidate_directory_and_record() {
            return Err(Error::StoreDurabilityUnknown {
                raw_code: POLICY_ERROR,
            });
        }
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
        match (result, close) {
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(io(PlatformOperation::Open, error)),
            (Err(_), Err(error)) => Err(io(PlatformOperation::Open, error)),
            (Ok(_), Ok(())) => Ok(()),
        }
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
    if meta.kind != ObjectKind::Directory || meta.reparse_point || !meta.trusted_known_folder {
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
    Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcePrincipal {
    System,
    Administrators,
    Ordinary,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AceKind {
    Allow,
    Deny,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AceFact {
    kind: AceKind,
    principal: AcePrincipal,
    mask: u32,
    inherited: bool,
}

const FULL_CONTROL_MASK: u32 = 0x001f01ff;
const MUTATION_MASK: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000;

/// Reduce an already-parsed native descriptor to closed policy facts. Every
/// ACE must be understood; no deny, inherited, unknown, duplicate, or extra
/// right is silently ignored. `allow_root_read` exists only for the known
/// ProgramData root, whose standard ACL may grant ordinary users read access.
fn reduce_security_descriptor(
    owner: Owner,
    dacl_present: bool,
    dacl_protected: bool,
    aces: &[AceFact],
    allow_root_read: bool,
) -> Result<SecurityDescriptor, i32> {
    if !matches!(owner, Owner::System | Owner::Administrators)
        || !dacl_present
        || aces.is_empty()
        || (!allow_root_read && !dacl_protected)
    {
        return Err(POLICY_ERROR);
    }
    let mut system = false;
    let mut administrators = false;
    let mut ordinary = false;
    for ace in aces {
        if ace.inherited || ace.kind != AceKind::Allow {
            return Err(POLICY_ERROR);
        }
        match ace.principal {
            AcePrincipal::System if ace.mask == FULL_CONTROL_MASK && !system => system = true,
            AcePrincipal::Administrators if ace.mask == FULL_CONTROL_MASK && !administrators => {
                administrators = true
            }
            AcePrincipal::Ordinary if allow_root_read && ace.mask & MUTATION_MASK == 0 => {
                ordinary = true
            }
            AcePrincipal::System
            | AcePrincipal::Administrators
            | AcePrincipal::Ordinary
            | AcePrincipal::Unknown => return Err(POLICY_ERROR),
        }
    }
    if !system || !administrators {
        return Err(POLICY_ERROR);
    }
    Ok(SecurityDescriptor {
        owner,
        dacl: if allow_root_read {
            Dacl {
                ordinary_user_access: ordinary,
                ..Dacl::PROGRAM_DATA_ROOT
            }
        } else {
            Dacl::PROTECTED
        },
    })
}

#[cfg(windows)]
#[allow(dead_code)]
mod native {
    //! Native adapter.  It is intentionally private; only the trusted helper
    //! entry point may construct it in a later integration task.
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
        EqualSid, GetAce, GetSecurityDescriptorControl, IsValidSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, WELL_KNOWN_SID_TYPE,
        WinAuthenticatedUserSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, WinWorldSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFinalPathNameByHandleW, OPEN_EXISTING, ReplaceFileW, VOLUME_NAME_DOS,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    pub(crate) struct NativeHandle {
        file: File,
        trusted_root: bool,
        parent_id: Option<u128>,
    }

    impl Clone for NativeHandle {
        fn clone(&self) -> Self {
            Self {
                file: self.file.try_clone().expect("native handle clone"),
                trusted_root: self.trusted_root,
                parent_id: self.parent_id,
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
    fn handle(
        path: PathBuf,
        trusted_root: bool,
        parent_id: Option<u128>,
        write: bool,
        directory: bool,
    ) -> Result<NativeHandle, i32> {
        let wide_path = wide(&path);
        let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
        if directory {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }
        let raw_handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                FILE_GENERIC_READ | if write { FILE_GENERIC_WRITE } else { 0 },
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                flags | FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if raw_handle == INVALID_HANDLE_VALUE {
            return Err(raw());
        }
        let file = unsafe { File::from_raw_handle(raw_handle as _) };
        Ok(NativeHandle {
            file,
            trusted_root,
            parent_id,
        })
    }
    fn object_id(handle: &NativeHandle) -> Result<u128, i32> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };
        let mut info = FILE_ID_INFO::default();
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.file.as_raw_handle() as _,
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(raw());
        }
        let mut low = [0u8; 8];
        let mut high = [0u8; 8];
        low.copy_from_slice(&info.FileId.Identifier[..8]);
        high.copy_from_slice(&info.FileId.Identifier[8..]);
        // Keep both the volume and complete 128-bit file identifier in the
        // portable scalar identity. This is a fold of held-handle facts, not
        // a lexical/path-derived identifier.
        Ok(u64::from_le_bytes(low) as u128
            ^ ((u64::from_le_bytes(high) as u128) << 64)
            ^ u128::from(info.VolumeSerialNumber))
    }

    fn final_path(handle: &NativeHandle) -> Result<PathBuf, i32> {
        let raw_handle = handle.file.as_raw_handle() as _;
        let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
        let mut buffer = vec![0u16; 512];
        loop {
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    raw_handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    flags,
                )
            };
            if length == 0 {
                return Err(raw());
            }
            if (length as usize) < buffer.len() {
                return Ok(PathBuf::from(std::ffi::OsString::from_wide(
                    &buffer[..length as usize],
                )));
            }
            if length as usize >= 32_768 {
                return Err(1);
            }
            buffer.resize(length as usize + 1, 0);
        }
    }

    fn is_direct_child(parent: &NativeHandle, child: &NativeHandle) -> Result<bool, i32> {
        let parent_path = final_path(parent)?;
        let child_path = final_path(child)?;
        let Some(child_parent) = child_path.parent() else {
            return Ok(false);
        };
        // The final-path query is made against both held handles. The ordinal
        // case-insensitive comparison matches Win32 path identity while
        // avoiding any lexical path-derived object ID.
        Ok(child_parent
            .to_string_lossy()
            .eq_ignore_ascii_case(&parent_path.to_string_lossy()))
    }

    fn open_child(parent: &NativeHandle, name: &str, directory: bool) -> Result<NativeHandle, i32> {
        let parent_id = object_id(parent)?;
        let path = final_path(parent)?.join(name);
        let child = handle(path, false, Some(parent_id), false, directory)?;
        if object_id(parent)? != parent_id || !is_direct_child(parent, &child)? {
            return Err(POLICY_ERROR);
        }
        Ok(child)
    }

    fn validate_child_file(
        calls: &mut SystemWindowsStoreCalls,
        parent: &NativeHandle,
        child: &NativeHandle,
    ) -> Result<(), i32> {
        let metadata = calls.metadata(child)?;
        if metadata.kind != ObjectKind::File
            || metadata.reparse_point
            || metadata.parent_id != Some(object_id(parent)?)
        {
            return Err(POLICY_ERROR);
        }
        validate_security(calls.security(child)?).map_err(|_| POLICY_ERROR)
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
        let create_error = if handle == INVALID_HANDLE_VALUE {
            Some(raw())
        } else {
            None
        };
        unsafe {
            LocalFree(descriptor.cast());
        }
        if let Some(raw_code) = create_error {
            return Err(raw_code);
        }
        Ok(unsafe { File::from_raw_handle(handle as _) })
    }

    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u8>, i32> {
        let mut bytes = vec![0u8; 68];
        let mut size = bytes.len() as u32;
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                bytes.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if ok == 0 {
            return Err(raw());
        }
        bytes.truncate(size as usize);
        Ok(bytes)
    }

    unsafe fn sid_kind(sid: PSID) -> AcePrincipal {
        let system = well_known(WinLocalSystemSid).ok();
        let administrators = well_known(WinBuiltinAdministratorsSid).ok();
        let ordinary = [
            well_known(WinWorldSid).ok(),
            well_known(WinAuthenticatedUserSid).ok(),
        ];
        if unsafe { IsValidSid(sid) } == 0 {
            return AcePrincipal::Unknown;
        }
        if system
            .as_deref()
            .is_some_and(|known| unsafe { EqualSid(sid, known.as_ptr().cast_mut().cast()) != 0 })
        {
            AcePrincipal::System
        } else if administrators
            .as_deref()
            .is_some_and(|known| unsafe { EqualSid(sid, known.as_ptr().cast_mut().cast()) != 0 })
        {
            AcePrincipal::Administrators
        } else if ordinary
            .iter()
            .flatten()
            .any(|known| unsafe { EqualSid(sid, known.as_ptr().cast_mut().cast()) != 0 })
        {
            AcePrincipal::Ordinary
        } else {
            AcePrincipal::Unknown
        }
    }

    fn parse_native_descriptor(
        owner_sid: PSID,
        dacl: *mut ACL,
        descriptor: PSECURITY_DESCRIPTOR,
        allow_root_read: bool,
    ) -> Result<SecurityDescriptor, i32> {
        (|| {
            if owner_sid.is_null() || dacl.is_null() || descriptor.is_null() {
                return Err(POLICY_ERROR);
            }
            let owner = unsafe { sid_kind(owner_sid) };
            let owner = match owner {
                AcePrincipal::System => Owner::System,
                AcePrincipal::Administrators => Owner::Administrators,
                _ => Owner::Other,
            };
            let mut present = 0;
            let mut defaulted = 0;
            let mut observed_dacl = std::ptr::null_mut();
            if unsafe {
                windows_sys::Win32::Security::GetSecurityDescriptorDacl(
                    descriptor,
                    &mut present,
                    &mut observed_dacl,
                    &mut defaulted,
                )
            } == 0
                || present == 0
                || observed_dacl.is_null()
                || observed_dacl != dacl
            {
                return Err(POLICY_ERROR);
            }
            let mut control = 0u16;
            let mut revision = 0u32;
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            {
                return Err(POLICY_ERROR);
            }
            let acl = unsafe { &*observed_dacl };
            if acl.AclRevision != 2 {
                return Err(POLICY_ERROR);
            }
            let mut facts = Vec::with_capacity(acl.AceCount as usize);
            for index in 0..acl.AceCount {
                let mut raw_ace = std::ptr::null_mut();
                if unsafe { GetAce(observed_dacl, index as u32, &mut raw_ace) } == 0
                    || raw_ace.is_null()
                {
                    return Err(POLICY_ERROR);
                }
                let header = unsafe { &*(raw_ace.cast::<ACE_HEADER>()) };
                if header.AceSize < std::mem::size_of::<ACCESS_ALLOWED_ACE>() as u16 {
                    return Err(POLICY_ERROR);
                }
                let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
                let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
                facts.push(AceFact {
                    kind: match header.AceType {
                        0 => AceKind::Allow,
                        1 => AceKind::Deny,
                        _ => AceKind::Unknown,
                    },
                    principal: unsafe { sid_kind(sid) },
                    mask: ace.Mask,
                    inherited: header.AceFlags & 0x10 != 0,
                });
            }
            reduce_security_descriptor(
                owner,
                true,
                control & SE_DACL_PROTECTED != 0,
                &facts,
                allow_root_read,
            )
        })()
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
            handle(path, true, None, false, true)
        }

        fn open_directory(
            &mut self,
            parent: &Self::Handle,
            name: &str,
        ) -> Result<Self::Handle, i32> {
            open_child(parent, name, true)
        }
        fn open_file(&mut self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
            open_child(parent, name, false)
        }
        fn metadata(&mut self, handle: &Self::Handle) -> Result<ObjectMetadata, i32> {
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_TAG_INFO, FILE_STANDARD_INFO, FileAttributeTagInfo,
                FileStandardInfo, GetFileInformationByHandleEx,
            };
            let mut tags = FILE_ATTRIBUTE_TAG_INFO::default();
            let tag_ok = unsafe {
                GetFileInformationByHandleEx(
                    handle.file.as_raw_handle() as _,
                    FileAttributeTagInfo,
                    (&mut tags as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                    std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
                )
            };
            if tag_ok == 0 {
                return Err(raw());
            }
            if tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || tags.ReparseTag != 0 {
                return Err(1);
            }
            let mut standard = FILE_STANDARD_INFO::default();
            let standard_ok = unsafe {
                GetFileInformationByHandleEx(
                    handle.file.as_raw_handle() as _,
                    FileStandardInfo,
                    (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                    std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
                )
            };
            if standard_ok == 0 || standard.EndOfFile < 0 {
                return Err(raw());
            }
            let kind = if standard.Directory {
                ObjectKind::Directory
            } else {
                ObjectKind::File
            };
            let file_id = object_id(handle)?;
            Ok(ObjectMetadata {
                kind,
                reparse_point: false,
                trusted_known_folder: handle.trusted_root,
                file_id,
                parent_id: handle.parent_id,
                size: standard.EndOfFile as u64,
            })
        }
        fn security(&mut self, handle: &Self::Handle) -> Result<SecurityDescriptor, i32> {
            let raw_handle = handle.file.as_raw_handle() as _;
            let mut owner = std::ptr::null_mut();
            let mut dacl = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let status = unsafe {
                GetSecurityInfo(
                    raw_handle,
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
            // GetSecurityInfo allocates one self-relative descriptor. Keep
            // exactly one owner for LocalFree, including hostile parse paths.
            let result = parse_native_descriptor(owner, dacl, descriptor, handle.trusted_root);
            unsafe {
                LocalFree(descriptor.cast());
            }
            result
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
            let parent_id = object_id(parent)?;
            let path = final_path(parent)?.join(name);
            let file = secured_create(&path)?;
            let created = NativeHandle {
                file,
                trusted_root: false,
                parent_id: Some(parent_id),
            };
            if object_id(parent)? != parent_id || !is_direct_child(parent, &created)? {
                return Err(POLICY_ERROR);
            }
            Ok(created)
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
            let parent_id = object_id(parent)?;
            let parent_path = final_path(parent)?;
            // Reopen both path operands with reparse-point-aware handles and
            // validate their held-handle containment immediately before the
            // unavoidable path-based ReplaceFileW call.
            let target_handle = open_child(parent, record_name, false)?;
            let replacement_handle = open_child(parent, temporary_name, false)?;
            if object_id(parent)? != parent_id
                || object_id(&target_handle)? == object_id(&replacement_handle)?
            {
                return Err(POLICY_ERROR);
            }
            validate_child_file(self, parent, &target_handle)?;
            validate_child_file(self, parent, &replacement_handle)?;
            drop(target_handle);
            drop(replacement_handle);
            let target = wide(&parent_path.join(record_name));
            let replacement = wide(&parent_path.join(temporary_name));
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
            let parent_id = object_id(parent)?;
            let child = open_child(parent, name, false)?;
            validate_child_file(self, parent, &child)?;
            drop(child);
            let path = final_path(parent)?.join(name);
            let result = std::fs::remove_file(path).map_err(|e| e.raw_os_error().unwrap_or(1));
            if object_id(parent)? != parent_id {
                return Err(POLICY_ERROR);
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtectedStore;

    #[derive(Clone)]
    struct TestHandle {
        name: String,
        metadata: ObjectMetadata,
        security: SecurityDescriptor,
        bytes: Vec<u8>,
        cursor: usize,
    }

    struct TestCalls {
        events: Vec<String>,
        record: Option<Vec<u8>>,
        replace_error: Option<i32>,
        fail_revalidation: bool,
        write_error: Option<i32>,
        close_error: Option<i32>,
        remove_error: Option<i32>,
        opened_records: usize,
    }

    impl TestCalls {
        fn new(record: Option<Vec<u8>>) -> Self {
            Self {
                events: Vec::new(),
                record,
                replace_error: None,
                fail_revalidation: false,
                write_error: None,
                close_error: None,
                remove_error: None,
                opened_records: 0,
            }
        }

        fn root() -> TestHandle {
            TestHandle {
                name: "ProgramData".into(),
                metadata: ObjectMetadata::program_data(1),
                security: SecurityDescriptor {
                    owner: Owner::System,
                    dacl: Dacl::PROGRAM_DATA_ROOT,
                },
                bytes: Vec::new(),
                cursor: 0,
            }
        }

        fn directory() -> TestHandle {
            TestHandle {
                name: "BootHop".into(),
                metadata: ObjectMetadata::protected_directory(2, 1),
                security: SecurityDescriptor::PROTECTED,
                bytes: Vec::new(),
                cursor: 0,
            }
        }

        fn file(&self, name: &str, bytes: Vec<u8>) -> TestHandle {
            TestHandle {
                name: name.into(),
                metadata: ObjectMetadata {
                    kind: ObjectKind::File,
                    reparse_point: false,
                    trusted_known_folder: false,
                    file_id: if name == RECORD_NAME { 3 } else { 4 },
                    parent_id: Some(2),
                    size: bytes.len() as u64,
                },
                security: SecurityDescriptor::PROTECTED,
                bytes,
                cursor: 0,
            }
        }
    }

    impl WindowsStoreCalls for TestCalls {
        type Handle = TestHandle;

        fn known_folder_program_data(&mut self) -> Result<Self::Handle, i32> {
            Ok(Self::root())
        }

        fn open_directory(&mut self, _: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
            assert_eq!(name, "BootHop");
            Ok(Self::directory())
        }

        fn open_file(&mut self, _: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
            if name != RECORD_NAME {
                return Err(2);
            }
            self.opened_records += 1;
            if self.fail_revalidation && self.opened_records > 1 {
                return Err(5);
            }
            self.record
                .clone()
                .map(|bytes| self.file(name, bytes))
                .ok_or(2)
        }

        fn metadata(&mut self, handle: &Self::Handle) -> Result<ObjectMetadata, i32> {
            Ok(handle.metadata.clone())
        }

        fn security(&mut self, handle: &Self::Handle) -> Result<SecurityDescriptor, i32> {
            Ok(handle.security)
        }

        fn read(&mut self, handle: &mut Self::Handle, bytes: &mut [u8]) -> Result<usize, i32> {
            let count = bytes
                .len()
                .min(handle.bytes.len().saturating_sub(handle.cursor));
            bytes[..count].copy_from_slice(&handle.bytes[handle.cursor..handle.cursor + count]);
            handle.cursor += count;
            Ok(count)
        }

        fn create_exclusive_file(
            &mut self,
            _: &Self::Handle,
            name: &str,
            security: &SecurityDescriptor,
        ) -> Result<Self::Handle, i32> {
            self.events.push(format!("create:{name}"));
            Ok(TestHandle {
                security: *security,
                ..self.file(name, Vec::new())
            })
        }

        fn write(&mut self, handle: &mut Self::Handle, bytes: &[u8]) -> Result<usize, i32> {
            self.events.push(format!("write:{}", handle.name));
            if let Some(error) = self.write_error {
                return Err(error);
            }
            handle.bytes.extend_from_slice(bytes);
            handle.metadata.size = handle.bytes.len() as u64;
            Ok(bytes.len())
        }

        fn flush(&mut self, handle: &Self::Handle) -> Result<(), i32> {
            self.events.push(format!("flush:{}", handle.name));
            Ok(())
        }

        fn close(&mut self, handle: Self::Handle) -> Result<(), i32> {
            self.events.push(format!("close:{}", handle.name));
            if handle.name == RECORD_NAME && self.record.is_none() {
                self.record = Some(handle.bytes);
            }
            if handle.name.starts_with(TEMP_PREFIX) {
                self.close_error.map_or(Ok(()), Err)
            } else {
                Ok(())
            }
        }

        fn replace_file(
            &mut self,
            _: &Self::Handle,
            temporary_name: &str,
            record_name: &str,
            flags: u32,
        ) -> Result<(), i32> {
            self.events
                .push(format!("replace:{temporary_name}:{record_name}:{flags}"));
            self.replace_error.map_or(Ok(()), Err)
        }

        fn remove_file(&mut self, _: &Self::Handle, name: &str) -> Result<(), i32> {
            self.events.push(format!("remove:{name}"));
            self.remove_error.map_or(Ok(()), Err)
        }
    }

    fn target() -> TargetRecord {
        let hex = include_str!("../../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
        let bytes: Vec<_> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        TargetRecord {
            boot_id: boothop_core::BootId(7),
            os: boothop_core::Os::Windows,
            identity: boothop_core::canonicalize(&boothop_core::parse_load_option(&bytes).unwrap())
                .unwrap(),
        }
    }

    fn ace(principal: AcePrincipal, mask: u32) -> AceFact {
        AceFact {
            kind: AceKind::Allow,
            principal,
            mask,
            inherited: false,
        }
    }

    fn exact() -> Vec<AceFact> {
        vec![
            ace(AcePrincipal::System, FULL_CONTROL_MASK),
            ace(AcePrincipal::Administrators, FULL_CONTROL_MASK),
        ]
    }

    #[test]
    fn descriptor_parser_accepts_only_explicit_system_and_admin_full_control() {
        let result = reduce_security_descriptor(Owner::System, true, true, &exact(), false);
        assert_eq!(result, Ok(SecurityDescriptor::PROTECTED));
    }

    #[test]
    fn descriptor_parser_rejects_hostile_owner_dacl_and_ace_shapes() {
        let hostile = [
            (Owner::Other, true, true, exact()),
            (Owner::System, false, true, exact()),
            (Owner::System, true, false, exact()),
            (
                Owner::System,
                true,
                true,
                vec![ace(AcePrincipal::Ordinary, FULL_CONTROL_MASK)],
            ),
            (
                Owner::System,
                true,
                true,
                vec![ace(AcePrincipal::Unknown, FULL_CONTROL_MASK)],
            ),
            (
                Owner::System,
                true,
                true,
                vec![AceFact {
                    kind: AceKind::Deny,
                    ..ace(AcePrincipal::System, FULL_CONTROL_MASK)
                }],
            ),
            (
                Owner::System,
                true,
                true,
                vec![AceFact {
                    inherited: true,
                    ..ace(AcePrincipal::System, FULL_CONTROL_MASK)
                }],
            ),
            (
                Owner::System,
                true,
                true,
                vec![
                    ace(AcePrincipal::System, FULL_CONTROL_MASK),
                    ace(AcePrincipal::Administrators, FULL_CONTROL_MASK),
                    ace(AcePrincipal::System, FULL_CONTROL_MASK),
                ],
            ),
        ];
        for (owner, present, protected, aces) in hostile {
            assert!(reduce_security_descriptor(owner, present, protected, &aces, false).is_err());
        }
    }

    #[test]
    fn descriptor_parser_rejects_extra_rights_and_allows_only_root_read_ace() {
        let mut extra = exact();
        extra[0].mask |= 0x8000_0000;
        assert!(reduce_security_descriptor(Owner::System, true, true, &extra, false).is_err());
        let mut root = exact();
        root.push(ace(AcePrincipal::Ordinary, 0x120089));
        assert!(reduce_security_descriptor(Owner::System, true, false, &root, true).is_ok());
        root[2].mask |= 2;
        assert!(reduce_security_descriptor(Owner::System, true, false, &root, true).is_err());
    }

    #[test]
    fn replacement_failure_preserves_artifact_and_never_retries_or_removes() {
        let bytes = encode_record(&target()).unwrap();
        for raw_code in [1176, 1177] {
            let mut calls = TestCalls::new(Some(bytes.clone()));
            calls.replace_error = Some(raw_code);
            let mut store =
                WindowsProtectedStore::open(calls, OperationCapability::for_testing()).unwrap();
            assert_eq!(
                store.save(&target()),
                Err(Error::StoreDurabilityUnknown { raw_code })
            );
            let calls = store.into_calls();
            assert_eq!(
                calls
                    .events
                    .iter()
                    .filter(|event| event.starts_with("replace:"))
                    .count(),
                1
            );
            assert!(
                !calls
                    .events
                    .iter()
                    .any(|event| event.starts_with("remove:"))
            );
        }
    }

    #[test]
    fn first_create_revalidation_failure_is_durability_unknown_and_preserves_final() {
        let mut calls = TestCalls::new(None);
        calls.fail_revalidation = true;
        let mut store =
            WindowsProtectedStore::open(calls, OperationCapability::for_testing()).unwrap();
        assert_eq!(
            store.save(&target()),
            Err(Error::StoreDurabilityUnknown {
                raw_code: POLICY_ERROR
            })
        );
        let calls = store.into_calls();
        assert!(
            calls
                .events
                .iter()
                .any(|event| event == "create:targets.json")
        );
        assert!(
            !calls
                .events
                .iter()
                .any(|event| event.starts_with("remove:"))
        );
    }

    #[test]
    fn pre_replace_cleanup_failure_is_reported_and_cleanup_is_attempted() {
        let bytes = encode_record(&target()).unwrap();
        let mut calls = TestCalls::new(Some(bytes));
        calls.write_error = Some(88);
        calls.remove_error = Some(91);
        let mut store =
            WindowsProtectedStore::open(calls, OperationCapability::for_testing()).unwrap();
        assert_eq!(
            store.save(&target()),
            Err(Error::PlatformIo {
                operation: PlatformOperation::Open,
                raw_code: 91,
            })
        );
        let calls = store.into_calls();
        assert!(
            calls
                .events
                .iter()
                .any(|event| event.starts_with("close:.targets-"))
        );
        assert!(
            calls
                .events
                .iter()
                .any(|event| event.starts_with("remove:.targets-"))
        );
    }
}
