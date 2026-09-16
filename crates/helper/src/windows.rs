//! Pure trusted Windows helper boundaries.
//!
//! Native process authentication, named pipes, and mutex handles are supplied
//! by later target-specific entry points. This module deliberately exposes
//! only injectable seams so host tests cannot perform privileged operations.

pub mod lock;
pub mod pipe;
pub use pipe::{PIPE_DACL, PIPE_MAX_BYTES, PIPE_NAME_PREFIX};

use boothop_core::Error;
use std::time::{Duration, Instant};

pub const OPERATION_MUTEX_NAME: &str = r"Global\BootHop.Operation.v1";
pub const OPERATION_MUTEX_TIMEOUT_MS: u32 = 30_000;
/// SDDL for the operation mutex: SYSTEM and built-in administrators only.
pub const OPERATION_MUTEX_DACL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// Fixed installation identities. These are deliberately constants rather
/// than helper arguments so a caller cannot redirect the trusted boundary.
pub const HELPER_IMAGE_PATH: &str = r"C:\Program Files\BootHop\boothop-helper.exe";
pub const GUI_IMAGE_PATH: &str = r"C:\Program Files\BootHop\boothop-gui.exe";

/// OS-backed mutex wait result. Abandonment is distinct from timeout and is
/// always treated as a fail-closed platform error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Acquired,
    Timeout,
    Abandoned,
}

pub trait OperationMutex {
    /// Create/open the fixed mutex. If this fails, the implementation must
    /// close any transient handle it created when the boundary is dropped.
    fn create(&mut self, name: &str, dacl: &str) -> Result<(), Error>;
    /// Wait for exclusive ownership. A timeout/abandonment is not ownership;
    /// implementations must close their native handle on Drop in that case.
    fn wait(&mut self, timeout_ms: u32) -> Result<WaitOutcome, Error>;
    /// Wait against one absolute operation deadline. Implementations may
    /// override this to pass the deadline directly to an OS boundary; the
    /// default computes the remaining budget exactly once and never creates a
    /// fresh timeout window.
    fn wait_until(&mut self, deadline: Instant) -> Result<WaitOutcome, Error> {
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Lock,
                raw_code: 1460,
            });
        }
        let remaining = deadline.duration_since(now);
        let timeout_ms = remaining.as_millis().min(u128::from(u32::MAX)) as u32;
        self.wait(timeout_ms)
    }
    /// Release an acquired mutex. The boundary owns and closes its handle on
    /// Drop regardless of whether acquisition or release succeeded.
    fn release(&mut self) -> Result<(), Error>;
}

/// Helper-owned RAII capability. The guard owns the fake/native boundary and
/// therefore remains alive until the enclosing response-sending stack frame
/// drops it.
pub struct WindowsOperationGuard<C: OperationMutex> {
    calls: C,
    released: bool,
}

impl<C: OperationMutex> WindowsOperationGuard<C> {
    pub fn acquire(calls: C) -> Result<Self, Error> {
        Self::acquire_until(
            calls,
            Instant::now() + Duration::from_millis(u64::from(OPERATION_MUTEX_TIMEOUT_MS)),
        )
    }

    pub fn acquire_until(mut calls: C, deadline: Instant) -> Result<Self, Error> {
        calls.create(OPERATION_MUTEX_NAME, OPERATION_MUTEX_DACL)?;
        match calls.wait_until(deadline) {
            Ok(WaitOutcome::Acquired) => Ok(Self {
                calls,
                released: false,
            }),
            Ok(WaitOutcome::Timeout) => Err(Error::Busy),
            Ok(WaitOutcome::Abandoned) => Err(Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Lock,
                raw_code: 0x0000_0080,
            }),
            Err(error) => Err(error),
        }
    }

    /// Run the operation while retaining the guard through callback return.
    pub fn with_operation<T>(
        mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        operation(&mut self)
    }

    pub fn calls(&self) -> &C {
        &self.calls
    }

    /// Finish an operation after the terminal response send. Release errors
    /// are returned as fail-closed platform errors and are never retried.
    pub fn finish(mut self) -> Result<(), Error> {
        self.release_once()
    }

    fn release_once(&mut self) -> Result<(), Error> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        self.calls.release()
    }
}

impl<C: OperationMutex> Drop for WindowsOperationGuard<C> {
    fn drop(&mut self) {
        if !self.released && self.release_once().is_err() {
            // Debug/test builds must remain testable without terminating the
            // harness. Production release builds fail closed because
            // continuing after a lock-release failure is unsafe.
            #[cfg(not(debug_assertions))]
            std::process::abort();
        }
    }
}
