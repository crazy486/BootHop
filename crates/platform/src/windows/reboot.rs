//! Planned Windows reboot boundary.
//!
//! The policy is portable and injectable.  The native implementation is
//! Windows-only and intentionally private; tests exercise only fake calls.

use boothop_core::RebootOutcome;

pub const SHUTDOWN_TIMEOUT_SECONDS: u32 = 0;
pub const FORCE_APPS_CLOSED: bool = false;
pub const REBOOT_AFTER_SHUTDOWN: bool = true;
pub const SHUTDOWN_REASON: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebootReply {
    Accepted,
    Rejected { raw_code: i32 },
    Unknown,
}

impl RebootReply {
    pub(crate) const fn into_core(self) -> RebootOutcome {
        match self {
            Self::Accepted => RebootOutcome::Accepted,
            Self::Rejected { .. } => RebootOutcome::Rejected,
            Self::Unknown => RebootOutcome::Unknown,
        }
    }
}

/// Injectable reboot boundary.  A reply is accepted only at the native call
/// boundary; loss of the process/transport after dispatch is Unknown.
pub trait RebootCalls {
    fn request_reboot(&mut self) -> RebootReply;
}

/// Execute one shutdown request inside its own exact-state privilege scope.
/// This is intentionally separate from the firmware environment privilege
/// helper, even though both use the same low-level token restoration policy.
pub fn with_shutdown_privilege<C, T, F>(
    calls: &mut C,
    operation: F,
) -> Result<T, boothop_core::Error>
where
    C: crate::windows::privilege::TokenCalls,
    F: FnOnce(&mut C) -> Result<T, boothop_core::Error>,
{
    crate::windows::privilege::with_privilege(
        calls,
        crate::windows::privilege::Privilege::Shutdown,
        operation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planned_boundary_has_exact_non_forced_reboot_contract() {
        assert_eq!(std::hint::black_box(SHUTDOWN_TIMEOUT_SECONDS), 0);
        assert!(!std::hint::black_box(FORCE_APPS_CLOSED));
        assert!(std::hint::black_box(REBOOT_AFTER_SHUTDOWN));
        assert_eq!(std::hint::black_box(SHUTDOWN_REASON), 0x8000_0000);
    }

    #[test]
    fn boundary_replies_preserve_semantic_outcomes() {
        assert_eq!(RebootReply::Accepted.into_core(), RebootOutcome::Accepted);
        assert_eq!(
            RebootReply::Rejected { raw_code: 5 }.into_core(),
            RebootOutcome::Rejected
        );
        assert_eq!(RebootReply::Unknown.into_core(), RebootOutcome::Unknown);
    }
}

#[cfg(windows)]
mod native {
    use super::with_shutdown_privilege;
    use super::*;
    use crate::windows::privilege::native::NativeTokenCalls;
    use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
    use windows_sys::Win32::System::Shutdown::{
        InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_OTHER,
    };

    #[allow(dead_code)]
    const ERROR_NOT_ALL_ASSIGNED: i32 = 1300;

    /// Native reboot calls have no public constructor.  The helper is the only
    /// production owner permitted to wire this backend.
    #[allow(dead_code)]
    pub(crate) struct SystemRebootCalls {
        token: NativeTokenCalls,
    }

    impl SystemRebootCalls {
        #[allow(dead_code)]
        fn new() -> Self {
            Self {
                token: NativeTokenCalls::new(),
            }
        }
    }

    impl RebootCalls for SystemRebootCalls {
        fn request_reboot(&mut self) -> RebootReply {
            // SeShutdownPrivilege has its own exact-state RAII scope and is
            // enabled only after core has completed BootNext readback.
            let result = with_shutdown_privilege(&mut self.token, |_| {
                unsafe { SetLastError(0) };
                let accepted = unsafe {
                    InitiateSystemShutdownExW(
                        std::ptr::null(),
                        std::ptr::null(),
                        SHUTDOWN_TIMEOUT_SECONDS,
                        FORCE_APPS_CLOSED as i32,
                        REBOOT_AFTER_SHUTDOWN as i32,
                        SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_MAJOR_OTHER,
                    )
                };
                let raw_code = unsafe { GetLastError() as i32 };
                if accepted == 0 {
                    Err(boothop_core::Error::PlatformIo {
                        operation: boothop_core::PlatformOperation::Reboot,
                        raw_code,
                    })
                } else {
                    Ok(())
                }
            });
            match result {
                Ok(()) => RebootReply::Accepted,
                Err(error) => RebootReply::Rejected {
                    raw_code: match error {
                        boothop_core::Error::PrivilegeUnavailable => ERROR_NOT_ALL_ASSIGNED,
                        boothop_core::Error::PrivilegeEnableFailed { raw_code }
                        | boothop_core::Error::PrivilegeRestoreFailed { raw_code }
                        | boothop_core::Error::PlatformIo { raw_code, .. } => raw_code,
                        _ => 1,
                    },
                },
            }
        }
    }
}
