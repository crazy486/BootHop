//! Injectable operation-mutex boundary. Native Win32 implementation belongs
//! to the authenticated pipe task; this file contains no OS calls.

pub use super::{
    OPERATION_MUTEX_DACL, OPERATION_MUTEX_NAME, OPERATION_MUTEX_TIMEOUT_MS, OperationMutex,
    WaitOutcome, WindowsOperationGuard,
};
use boothop_core::Error;

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
