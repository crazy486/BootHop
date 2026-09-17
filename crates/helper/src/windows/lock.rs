//! Injectable operation-mutex boundary. Native Win32 implementation belongs
//! to the authenticated pipe task; this file contains no OS calls.

pub use super::{
    OPERATION_MUTEX_DACL, OPERATION_MUTEX_NAME, OPERATION_MUTEX_TIMEOUT_MS, OperationMutex,
    WaitOutcome, WindowsOperationGuard,
};
use boothop_core::Error;
#[cfg(windows)]
use boothop_core::PlatformOperation;

pub fn validate_existing_mutex_dacl(sddl: &str) -> bool {
    sddl == super::OPERATION_MUTEX_DACL
}

#[derive(Debug)]
pub struct FakeOperationMutex {
    pub events: Vec<&'static str>,
    pub wait_outcome: WaitOutcome,
    pub create_error: Option<Error>,
    pub release_error: Option<Error>,
}

impl Default for FakeOperationMutex {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            wait_outcome: WaitOutcome::Acquired,
            create_error: None,
            release_error: None,
        }
    }
}

impl OperationMutex for FakeOperationMutex {
    fn create(&mut self, name: &str, dacl: &str) -> Result<(), Error> {
        self.events.push(
            if name == super::OPERATION_MUTEX_NAME && dacl == super::OPERATION_MUTEX_DACL {
                "create-exact"
            } else {
                "create-invalid"
            },
        );
        self.create_error.take().map_or(Ok(()), Err)
    }

    fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
        self.events.push("wait");
        Ok(self.wait_outcome)
    }

    fn release(&mut self) -> Result<(), Error> {
        self.events.push("release");
        self.release_error.take().map_or(Ok(()), Err)
    }
}

#[cfg(windows)]
pub mod native {
    use super::*;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, SetLastError, WAIT_ABANDONED_0,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::System::Threading::{
        CreateMutexExW, MUTEX_ALL_ACCESS, ReleaseMutex, WaitForSingleObject,
    };

    /// Native mutex handle owner. Drop closes the handle even if creation,
    /// wait, or release fails; release is never attempted without ownership.
    #[derive(Default)]
    pub struct SystemOperationMutex {
        handle: Option<HANDLE>,
        acquired: bool,
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn existing_mutex_has_protected_dacl(handle: HANDLE) -> Result<bool, Error> {
        let mut needed = 0;
        let first_ok = unsafe {
            GetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                0,
                &mut needed,
            )
        };
        let first_error = unsafe { GetLastError() };
        if first_ok != 0 || needed == 0 {
            return Err(Error::PlatformIo {
                operation: PlatformOperation::Security,
                raw_code: first_error as i32,
            });
        }
        let mut descriptor = vec![0u8; needed as usize];
        if unsafe {
            GetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION,
                descriptor.as_mut_ptr().cast(),
                descriptor.len() as u32,
                &mut needed,
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            return Err(Error::PlatformIo {
                operation: PlatformOperation::Security,
                raw_code: code as i32,
            });
        }
        let mut sddl = std::ptr::null_mut();
        let mut sddl_len = 0;
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.as_mut_ptr().cast::<core::ffi::c_void>(),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                &mut sddl_len,
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            return Err(Error::PlatformIo {
                operation: PlatformOperation::Security,
                raw_code: code as i32,
            });
        }
        let value = unsafe { std::slice::from_raw_parts(sddl, sddl_len as usize) };
        let value = String::from_utf16(value).map_err(|_| Error::PlatformIo {
            operation: PlatformOperation::Security,
            raw_code: 5,
        });
        let matches = value.map(|value| validate_existing_mutex_dacl(value.trim_end_matches('\0')));
        let free_error = unsafe { GetLastError() };
        unsafe { LocalFree(sddl.cast()) };
        let _ = free_error;
        matches
    }

    impl OperationMutex for SystemOperationMutex {
        fn create(&mut self, name: &str, dacl: &str) -> Result<(), Error> {
            let name = wide(name);
            let dacl = wide(dacl);
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    dacl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            };
            if converted == 0 {
                let code = unsafe { GetLastError() };
                if !descriptor.is_null() {
                    unsafe { LocalFree(descriptor) };
                }
                return Err(Error::PlatformIo {
                    operation: PlatformOperation::Security,
                    raw_code: code as i32,
                });
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            unsafe { SetLastError(0) };
            let handle = unsafe { CreateMutexExW(&attributes, name.as_ptr(), 0, MUTEX_ALL_ACCESS) };
            let create_error = unsafe { GetLastError() };
            unsafe { LocalFree(descriptor) };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return Err(Error::PlatformIo {
                    operation: PlatformOperation::Lock,
                    raw_code: create_error as i32,
                });
            }
            if create_error == 183 {
                match existing_mutex_has_protected_dacl(handle) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        unsafe { CloseHandle(handle) };
                        return Err(Error::PlatformIo {
                            operation: PlatformOperation::Security,
                            raw_code: 5,
                        });
                    }
                }
            }
            self.handle = Some(handle);
            Ok(())
        }

        fn wait(&mut self, timeout_ms: u32) -> Result<WaitOutcome, Error> {
            let handle = self.handle.ok_or(Error::UnsupportedFormat)?;
            let result = unsafe { WaitForSingleObject(handle, timeout_ms) };
            match result {
                WAIT_OBJECT_0 => {
                    self.acquired = true;
                    Ok(WaitOutcome::Acquired)
                }
                WAIT_TIMEOUT => Ok(WaitOutcome::Timeout),
                WAIT_ABANDONED_0 => Ok(WaitOutcome::Abandoned),
                _ => Err(Error::PlatformIo {
                    operation: PlatformOperation::Lock,
                    raw_code: unsafe { GetLastError() as i32 },
                }),
            }
        }

        fn release(&mut self) -> Result<(), Error> {
            if !self.acquired {
                return Ok(());
            }
            if unsafe { ReleaseMutex(self.handle.ok_or(Error::UnsupportedFormat)?) } == 0 {
                return Err(Error::PlatformIo {
                    operation: PlatformOperation::Lock,
                    raw_code: unsafe { GetLastError() as i32 },
                });
            }
            self.acquired = false;
            Ok(())
        }
    }

    impl Drop for SystemOperationMutex {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                unsafe { CloseHandle(handle) };
            }
        }
    }
}
