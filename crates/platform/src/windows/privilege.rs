//! Scoped Windows token privileges.
//!
//! The policy in this module is portable and testable without a Windows host.
//! The direct Win32 adapter is compiled only on Windows and is kept private to
//! the firmware backend.

use boothop_core::Error;
use std::marker::PhantomData;

pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_QUERY: u32 = 0x0008;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x0002;
pub const ERROR_NOT_ALL_ASSIGNED: i32 = 1300;
pub const ERROR_NO_SUCH_PRIVILEGE: i32 = 1313;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Privilege {
    SystemEnvironment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Luid(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenHandle(pub usize);

/// A complete, owned representation of the variable-length TOKEN_PRIVILEGES
/// returned by AdjustTokenPrivileges.  The vector is deliberately not reduced
/// to the one privilege being enabled: restoration must replay exactly what
/// the OS returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenPrivileges {
    entries: Vec<(Luid, u32)>,
}

impl TokenPrivileges {
    pub fn new(entries: Vec<(Luid, u32)>) -> Self {
        Self { entries }
    }

    pub fn single(luid: Luid, attributes: u32) -> Self {
        Self::new(vec![(luid, attributes)])
    }

    pub(crate) fn entries(&self) -> &[(Luid, u32)] {
        &self.entries
    }
}

/// Injectable token boundary.  Implementations must return the prior state
/// written by AdjustTokenPrivileges in `previous_state`, including all
/// returned entries.
pub trait TokenCalls {
    fn open_process_token(&mut self, desired_access: u32) -> Result<TokenHandle, i32>;
    fn lookup_privilege_value(&mut self, privilege: Privilege) -> Result<Luid, i32>;
    fn set_last_error(&mut self, code: i32);
    fn last_error(&mut self) -> i32;
    fn adjust_token_privileges(
        &mut self,
        token: TokenHandle,
        new_state: &TokenPrivileges,
        previous_state: &mut TokenPrivileges,
    ) -> bool;
    fn close_handle(&mut self, token: TokenHandle) -> Result<(), i32>;
}

/// Run exactly one firmware operation with SeSystemEnvironmentPrivilege
/// enabled, then restore the exact prior token state and close the handle.
/// Restoration failure always supersedes the operation result.
pub fn with_system_environment_privilege<C, T, F>(calls: &mut C, operation: F) -> Result<T, Error>
where
    C: TokenCalls,
    F: FnOnce(&mut C) -> Result<T, Error>,
{
    let mut scope = PrivilegeScope::acquire(calls)?;
    if let Err(error) = scope.enable() {
        return scope.finish(Err(error));
    }
    let result = operation(scope.calls_mut());
    scope.finish(result)
}

struct PrivilegeScope<C: TokenCalls> {
    calls: *mut C,
    handle: TokenHandle,
    prior: TokenPrivileges,
    closed: bool,
    restored: bool,
    marker: PhantomData<C>,
}

impl<C: TokenCalls> PrivilegeScope<C> {
    fn acquire(calls: &mut C) -> Result<Self, Error> {
        let handle = match calls.open_process_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) {
            Ok(handle) => handle,
            Err(raw_code) => return Err(Error::PrivilegeEnableFailed { raw_code }),
        };
        let calls_ptr = calls as *mut C;
        match calls.lookup_privilege_value(Privilege::SystemEnvironment) {
            Ok(luid) => Ok(Self {
                calls: calls_ptr,
                handle,
                prior: TokenPrivileges::single(luid, 0),
                closed: false,
                restored: false,
                marker: PhantomData,
            }),
            Err(raw_code) => {
                let close_result = calls.close_handle(handle);
                let error = if raw_code == ERROR_NO_SUCH_PRIVILEGE {
                    Error::PrivilegeUnavailable
                } else {
                    Error::PrivilegeEnableFailed { raw_code }
                };
                if let Err(close_code) = close_result {
                    return Err(Error::PrivilegeRestoreFailed {
                        raw_code: close_code,
                    });
                }
                Err(error)
            }
        }
    }

    fn calls_mut(&mut self) -> &mut C {
        // SAFETY: the scope is the sole owner of the mutable borrow for its
        // lifetime; the raw pointer only exists to let Drop restore on unwind.
        unsafe { &mut *self.calls }
    }

    fn enable(&mut self) -> Result<(), Error> {
        let luid = self.prior.entries()[0].0;
        let requested = TokenPrivileges::single(luid, SE_PRIVILEGE_ENABLED);
        let handle = self.handle;
        let calls = unsafe { &mut *self.calls };
        calls.set_last_error(0);
        let success = calls.adjust_token_privileges(handle, &requested, &mut self.prior);
        let raw_code = calls.last_error();
        if !success || raw_code == ERROR_NOT_ALL_ASSIGNED {
            return Err(Error::PrivilegeEnableFailed { raw_code });
        }
        Ok(())
    }

    fn finish<T>(mut self, result: Result<T, Error>) -> Result<T, Error> {
        let restore_error = self.restore_and_close();
        match restore_error {
            Some(error) => Err(error),
            None => result,
        }
    }

    fn restore_and_close(&mut self) -> Option<Error> {
        if self.restored {
            return None;
        }
        self.restored = true;
        let handle = self.handle;
        let calls = unsafe { &mut *self.calls };
        calls.set_last_error(0);
        let mut ignored_previous = TokenPrivileges::new(Vec::new());
        let prior = self.prior.clone();
        let success = calls.adjust_token_privileges(handle, &prior, &mut ignored_previous);
        let raw_code = calls.last_error();
        let restore_error = if !success || raw_code == ERROR_NOT_ALL_ASSIGNED {
            Some(Error::PrivilegeRestoreFailed { raw_code })
        } else {
            None
        };
        let close_error = if !self.closed {
            self.closed = true;
            calls
                .close_handle(handle)
                .err()
                .map(|raw_code| Error::PrivilegeRestoreFailed { raw_code })
        } else {
            None
        };
        restore_error.or(close_error)
    }
}

impl<C: TokenCalls> Drop for PrivilegeScope<C> {
    fn drop(&mut self) {
        let _ = self.restore_and_close();
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, LUID as WinLuid, SetLastError,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
        SE_SYSTEM_ENVIRONMENT_NAME, TOKEN_PRIVILEGES,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    pub(crate) struct NativeTokenCalls;

    impl NativeTokenCalls {
        pub(crate) fn new() -> Self {
            Self
        }
    }

    fn raw_error() -> i32 {
        unsafe { GetLastError() as i32 }
    }

    fn as_handle(handle: TokenHandle) -> HANDLE {
        handle.0 as *mut c_void
    }

    fn as_luid(luid: Luid) -> WinLuid {
        WinLuid {
            LowPart: luid.0 as u32,
            HighPart: (luid.0 >> 32) as i32,
        }
    }

    fn from_luid(luid: WinLuid) -> Luid {
        Luid((u64::from(luid.HighPart as u32) << 32) | u64::from(luid.LowPart))
    }

    impl TokenCalls for NativeTokenCalls {
        fn open_process_token(&mut self, desired_access: u32) -> Result<TokenHandle, i32> {
            let mut token: HANDLE = null_mut();
            // -1 is the documented pseudo-handle for the current process and
            // avoids importing any process API into this narrow backend.
            let current_process = usize::MAX as HANDLE;
            unsafe { SetLastError(0) };
            let success = unsafe { OpenProcessToken(current_process, desired_access, &mut token) };
            if success == 0 {
                Err(raw_error())
            } else {
                Ok(TokenHandle(token as usize))
            }
        }

        fn lookup_privilege_value(&mut self, privilege: Privilege) -> Result<Luid, i32> {
            let name = match privilege {
                Privilege::SystemEnvironment => SE_SYSTEM_ENVIRONMENT_NAME,
            };
            let mut luid = WinLuid::default();
            unsafe { SetLastError(0) };
            let success = unsafe { LookupPrivilegeValueW(null(), name, &mut luid) };
            if success == 0 {
                Err(raw_error())
            } else {
                Ok(from_luid(luid))
            }
        }

        fn set_last_error(&mut self, code: i32) {
            unsafe { SetLastError(code as u32) }
        }

        fn last_error(&mut self) -> i32 {
            raw_error()
        }

        fn adjust_token_privileges(
            &mut self,
            token: TokenHandle,
            new_state: &TokenPrivileges,
            previous_state: &mut TokenPrivileges,
        ) -> bool {
            let Some(&(luid, attributes)) = new_state.entries().first() else {
                return false;
            };
            let requested = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: as_luid(luid),
                    Attributes: attributes,
                }],
            };
            // A generous fixed buffer keeps the prior variable-length result
            // intact. The operation adjusts one privilege, so Windows returns
            // one prior entry; no synthesized state is used for restoration.
            let mut previous_buffer = vec![0u8; 64 * 1024];
            let mut return_length = 0u32;
            let success = unsafe {
                AdjustTokenPrivileges(
                    as_handle(token),
                    0,
                    &requested,
                    size_of::<TOKEN_PRIVILEGES>() as u32,
                    previous_buffer.as_mut_ptr().cast::<TOKEN_PRIVILEGES>(),
                    &mut return_length,
                )
            };
            if return_length < size_of::<u32>() as u32 {
                previous_state.entries.clear();
            } else {
                let count = unsafe {
                    previous_buffer
                        .as_ptr()
                        .cast::<TOKEN_PRIVILEGES>()
                        .read_unaligned()
                        .PrivilegeCount
                } as usize;
                let available =
                    (return_length as usize - size_of::<u32>()) / size_of::<LUID_AND_ATTRIBUTES>();
                let count = count.min(available);
                let entries = unsafe {
                    std::slice::from_raw_parts(
                        previous_buffer
                            .as_ptr()
                            .add(size_of::<u32>())
                            .cast::<LUID_AND_ATTRIBUTES>(),
                        count,
                    )
                };
                previous_state.entries = entries
                    .iter()
                    .map(|entry| (from_luid(entry.Luid), entry.Attributes))
                    .collect();
            }
            success != 0
        }

        fn close_handle(&mut self, token: TokenHandle) -> Result<(), i32> {
            unsafe { SetLastError(0) };
            if unsafe { CloseHandle(as_handle(token)) } == 0 {
                Err(raw_error())
            } else {
                Ok(())
            }
        }
    }
}
