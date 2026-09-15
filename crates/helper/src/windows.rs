//! Pure trusted Windows helper boundaries.
//!
//! Native process authentication, named pipes, and mutex handles are supplied
//! by later target-specific entry points. This module deliberately exposes
//! only injectable seams so host tests cannot perform privileged operations.

pub mod lock;

use crate::dispatch::SendResult;
use boothop_core::{Error, Platform, Request};

pub const OPERATION_MUTEX_NAME: &str = r"Global\BootHop.Operation.v1";
pub const OPERATION_MUTEX_TIMEOUT_MS: u32 = 30_000;
/// SDDL for the operation mutex: SYSTEM and built-in administrators only.
pub const OPERATION_MUTEX_DACL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// OS-backed mutex wait result. Abandonment is distinct from timeout and is
/// always treated as a fail-closed platform error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Acquired,
    Timeout,
    Abandoned,
}

pub trait OperationMutex {
    fn create(&mut self, name: &str, dacl: &str) -> Result<(), Error>;
    fn wait(&mut self, timeout_ms: u32) -> Result<WaitOutcome, Error>;
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
    pub fn acquire(mut calls: C) -> Result<Self, Error> {
        calls.create(OPERATION_MUTEX_NAME, OPERATION_MUTEX_DACL)?;
        match calls.wait(OPERATION_MUTEX_TIMEOUT_MS) {
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
}

impl<C: OperationMutex> Drop for WindowsOperationGuard<C> {
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            let _ = self.calls.release();
        }
    }
}

/// Dispatches a decoded intent through the shared state machine with the
/// Windows host fixed by this function. The guard must be held by the caller
/// until its terminal response send returns.
pub fn run_windows(
    request: Request,
    platform: &mut impl Platform,
    send: &mut SendResult<'_>,
) -> Result<(), Error> {
    send(boothop_core::execute(
        request,
        boothop_core::Os::Windows,
        platform,
    ))
}

/// Production wiring hook: authentication and guard acquisition happen before
/// this closure constructs the native platform. The guard stays in scope while
/// `run_windows` invokes the terminal response callback.
pub fn dispatch_authenticated<C, P>(
    authenticate: impl FnOnce() -> Result<(), Error>,
    acquire: impl FnOnce() -> Result<WindowsOperationGuard<C>, Error>,
    request: Request,
    construct: impl FnOnce(&WindowsOperationGuard<C>) -> Result<P, Error>,
    send: &mut SendResult<'_>,
) -> Result<(), Error>
where
    C: OperationMutex,
    P: Platform,
{
    authenticate()?;
    let guard = acquire()?;
    let mut platform = construct(&guard)?;
    run_windows(request, &mut platform, send)
}
