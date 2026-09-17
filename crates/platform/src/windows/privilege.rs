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
pub const ERROR_INVALID_DATA: i32 = 13;

#[cfg(any(windows, test))]
fn previous_state_layout_valid(
    return_length: usize,
    count: usize,
    capacity: usize,
    entry_size: usize,
) -> bool {
    if return_length > capacity || entry_size == 0 {
        return false;
    }
    // A zero-entry TOKEN_PRIVILEGES result is represented by its DWORD
    // PrivilegeCount header alone. Do not accept a larger buffer with no
    // entries: those bytes would be unconsumed native state.
    if count == 0 {
        return_length == size_of::<u32>()
    } else {
        count
            .checked_mul(entry_size)
            .and_then(|entries| entries.checked_add(size_of::<u32>()))
            == Some(return_length)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Privilege {
    SystemEnvironment,
    Shutdown,
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

/// The result of one native AdjustTokenPrivileges call.  The last-error value
/// is captured inside the native call boundary, before its variable-length
/// PreviousState buffer is inspected or copied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenAdjustment {
    pub success: bool,
    pub last_error: i32,
    pub previous_state: TokenPrivileges,
    /// False means the native PreviousState was malformed and cannot safely be
    /// replayed. This is distinct from a valid zero-entry state.
    pub previous_state_valid: bool,
}

impl TokenPrivileges {
    pub fn new(entries: Vec<(Luid, u32)>) -> Self {
        Self { entries }
    }

    pub fn single(luid: Luid, attributes: u32) -> Self {
        Self::new(vec![(luid, attributes)])
    }

    #[cfg(windows)]
    pub(crate) fn entries(&self) -> &[(Luid, u32)] {
        &self.entries
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Injectable token boundary.  Implementations must return the prior state
/// written by AdjustTokenPrivileges in `previous_state`, including all
/// returned entries.
pub trait TokenCalls {
    fn open_process_token(&mut self, desired_access: u32) -> Result<TokenHandle, i32>;
    fn lookup_privilege_value(&mut self, privilege: Privilege) -> Result<Luid, i32>;
    fn set_last_error(&mut self, code: i32);
    fn adjust_token_privileges(
        &mut self,
        token: TokenHandle,
        new_state: &TokenPrivileges,
    ) -> TokenAdjustment;
    fn close_handle(&mut self, token: TokenHandle) -> Result<(), i32>;
}

/// Run exactly one firmware operation with SeSystemEnvironmentPrivilege
/// enabled, then restore the exact prior token state and close the handle.
/// Restoration failure always supersedes the operation result.
pub fn with_privilege<C, T, F>(
    calls: &mut C,
    privilege: Privilege,
    operation: F,
) -> Result<T, Error>
where
    C: TokenCalls,
    F: FnOnce(&mut C) -> Result<T, Error>,
{
    let mut scope = PrivilegeScope::acquire(calls, privilege)?;
    if let Err(error) = scope.enable() {
        return scope.finish(Err(error));
    }
    let result = operation(scope.calls_mut());
    scope.finish(result)
}

pub fn with_system_environment_privilege<C, T, F>(calls: &mut C, operation: F) -> Result<T, Error>
where
    C: TokenCalls,
    F: FnOnce(&mut C) -> Result<T, Error>,
{
    with_privilege(calls, Privilege::SystemEnvironment, operation)
}

struct PrivilegeScope<C: TokenCalls> {
    calls: *mut C,
    handle: TokenHandle,
    privilege_luid: Luid,
    prior: Option<TokenPrivileges>,
    adjustment_attempted: bool,
    prior_state_valid: bool,
    closed: bool,
    restored: bool,
    marker: PhantomData<C>,
}

impl<C: TokenCalls> PrivilegeScope<C> {
    fn acquire(calls: &mut C, privilege: Privilege) -> Result<Self, Error> {
        let handle = match calls.open_process_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) {
            Ok(handle) => handle,
            Err(raw_code) => return Err(Error::PrivilegeEnableFailed { raw_code }),
        };
        let calls_ptr = calls as *mut C;
        match calls.lookup_privilege_value(privilege) {
            Ok(luid) => Ok(Self {
                calls: calls_ptr,
                handle,
                privilege_luid: luid,
                prior: None,
                adjustment_attempted: false,
                prior_state_valid: true,
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
        let requested = TokenPrivileges::single(self.privilege_luid, SE_PRIVILEGE_ENABLED);
        let handle = self.handle;
        let calls = unsafe { &mut *self.calls };
        calls.set_last_error(0);
        let adjustment = calls.adjust_token_privileges(handle, &requested);
        // The native implementation snapshots GetLastError before parsing
        // PreviousState; do not perform another ambient last-error read here.
        self.adjustment_attempted = true;
        self.prior = Some(adjustment.previous_state.clone());
        self.prior_state_valid = adjustment.previous_state_valid;
        let raw_code = if adjustment.last_error == 0 && !adjustment.previous_state_valid {
            ERROR_INVALID_DATA
        } else {
            adjustment.last_error
        };
        if !adjustment.success
            || raw_code == ERROR_NOT_ALL_ASSIGNED
            || !adjustment.previous_state_valid
        {
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
        let restore_error = if !self.prior_state_valid {
            Some(Error::PrivilegeRestoreFailed {
                raw_code: ERROR_INVALID_DATA,
            })
        } else if !self.adjustment_attempted
            || self.prior.as_ref().is_none_or(TokenPrivileges::is_empty)
        {
            None
        } else {
            let prior = self.prior.as_ref().expect("checked above").clone();
            calls.set_last_error(0);
            let adjustment = calls.adjust_token_privileges(handle, &prior);
            let raw_code = adjustment.last_error;
            if !adjustment.success || raw_code == ERROR_NOT_ALL_ASSIGNED {
                Some(Error::PrivilegeRestoreFailed { raw_code })
            } else if !adjustment.previous_state_valid {
                Some(Error::PrivilegeRestoreFailed {
                    raw_code: ERROR_INVALID_DATA,
                })
            } else {
                None
            }
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
        if self.restore_and_close().is_some() {
            // Continuing after an implicit cleanup failure could leave a
            // privilege enabled. Explicit normal paths return the same error;
            // unwind paths must terminate rather than swallow it.
            std::process::abort();
        }
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
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_SHUTDOWN_NAME,
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
                Privilege::Shutdown => SE_SHUTDOWN_NAME,
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

        fn adjust_token_privileges(
            &mut self,
            token: TokenHandle,
            new_state: &TokenPrivileges,
        ) -> TokenAdjustment {
            let Some(&(luid, attributes)) = new_state.entries().first() else {
                return TokenAdjustment {
                    success: false,
                    last_error: ERROR_INVALID_DATA,
                    previous_state: TokenPrivileges::new(Vec::new()),
                    previous_state_valid: true,
                };
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
            #[repr(C)]
            struct PreviousPrivileges {
                count: u32,
                // The first entry begins at the same aligned offset as the
                // flexible array in TOKEN_PRIVILEGES.
                entries: [LUID_AND_ATTRIBUTES; 4096],
            }
            let mut previous_buffer = Box::new(PreviousPrivileges {
                count: 0,
                entries: [LUID_AND_ATTRIBUTES::default(); 4096],
            });
            let mut return_length = 0u32;
            let capacity = size_of::<PreviousPrivileges>();
            let success = unsafe {
                AdjustTokenPrivileges(
                    as_handle(token),
                    0,
                    &requested,
                    size_of::<TOKEN_PRIVILEGES>() as u32,
                    (&mut *previous_buffer as *mut PreviousPrivileges).cast::<TOKEN_PRIVILEGES>(),
                    &mut return_length,
                )
            };
            // Capture the ambient error before inspecting or copying the
            // variable-length output buffer; those operations must not alter
            // the native call's diagnostic.
            let last_error = raw_error();
            let malformed = !previous_state_layout_valid(
                return_length as usize,
                previous_buffer.count as usize,
                capacity,
                size_of::<LUID_AND_ATTRIBUTES>(),
            );
            let count = previous_buffer.count as usize;
            let malformed = malformed || count > 4096;
            if !malformed {
                let previous_state = previous_buffer.entries[..count]
                    .iter()
                    .map(|entry| (from_luid(entry.Luid), entry.Attributes))
                    .collect();
                return TokenAdjustment {
                    success: success != 0,
                    // This read is intentionally adjacent to the native call,
                    // before any output-buffer validation or allocation/copying.
                    last_error,
                    previous_state: TokenPrivileges {
                        entries: previous_state,
                    },
                    previous_state_valid: true,
                };
            }
            TokenAdjustment {
                success: success != 0,
                // This read is intentionally adjacent to the native call,
                // before any output-buffer validation or allocation/copying.
                last_error,
                previous_state: TokenPrivileges::new(Vec::new()),
                previous_state_valid: !malformed,
            }
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

#[cfg(test)]
mod tests {
    use super::previous_state_layout_valid;

    #[test]
    fn malformed_previous_state_lengths_and_counts_are_rejected() {
        assert!(previous_state_layout_valid(16, 1, 64, 12));
        assert!(!previous_state_layout_valid(28, 1, 64, 12));
        assert!(previous_state_layout_valid(28, 2, 64, 12));
        assert!(!previous_state_layout_valid(15, 1, 64, 12));
        assert!(!previous_state_layout_valid(17, 1, 64, 12));
        assert!(previous_state_layout_valid(4, 0, 64, 12));
        assert!(!previous_state_layout_valid(16, 0, 64, 12));
    }
}
