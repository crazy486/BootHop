//! Windows GUI-to-helper transport boundary.
//!
//! The semantic request/response exchange is shared with the Linux client;
//! this module owns only the fixed Windows launch and named-pipe session.
//! Native calls live in `native` and are compiled only for Windows. Tests use
//! the `WindowsBoundary` trait and never create a pipe or display UAC.

use super::{ClientError, TransportError, run_exchange};
use boothop_core::{Report, Request};
use boothop_protocol::RequestId;
use std::time::Duration;

pub const GUI_IMAGE_PATH: &str = r"C:\Program Files\BootHop\boothop-gui.exe";
pub const HELPER_IMAGE_PATH: &str = r"C:\Program Files\BootHop\boothop-helper.exe";
pub const GUI_EXECUTION_LEVEL: &str = "asInvoker";
pub const HELPER_RUNAS_VERB: &str = "runas";
pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\BootHop.";
pub const PIPE_DACL_SUFFIX: &str = ")(A;;GRGW;;;SY)(A;;GRGW;;;BA)";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsLaunchSpec {
    program: &'static str,
    verb: &'static str,
    args: Vec<String>,
    gui_image: &'static str,
    gui_execution_level: &'static str,
    see_mask_nocloseprocess: bool,
}

impl WindowsLaunchSpec {
    pub fn for_request(request_id: RequestId, gui_pid: u32) -> Self {
        Self {
            program: HELPER_IMAGE_PATH,
            verb: HELPER_RUNAS_VERB,
            args: vec![
                "--version=2".to_owned(),
                format!("--request-id={}", request_id.as_str()),
                format!("--gui-pid={gui_pid}"),
            ],
            gui_image: GUI_IMAGE_PATH,
            gui_execution_level: GUI_EXECUTION_LEVEL,
            see_mask_nocloseprocess: true,
        }
    }
    pub fn program(&self) -> &'static str {
        self.program
    }
    pub fn verb(&self) -> &'static str {
        self.verb
    }
    pub fn args(&self) -> &[String] {
        &self.args
    }
    pub fn gui_image(&self) -> &'static str {
        self.gui_image
    }
    pub fn gui_execution_level(&self) -> &'static str {
        self.gui_execution_level
    }
    pub fn see_mask_nocloseprocess(&self) -> bool {
        self.see_mask_nocloseprocess
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPipeSpec {
    request_id: RequestId,
    user_sid: String,
    name: String,
    dacl: String,
    first_instance: bool,
    reject_remote: bool,
}

impl WindowsPipeSpec {
    pub fn for_request(request_id: RequestId, user_sid: &str) -> Self {
        let name = format!("{PIPE_NAME_PREFIX}{}", request_id.as_str());
        let dacl = format!("D:P(A;;GRGW;;;{user_sid}){PIPE_DACL_SUFFIX}");
        Self {
            request_id,
            user_sid: user_sid.to_owned(),
            name,
            dacl,
            first_instance: true,
            reject_remote: true,
        }
    }
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    pub fn user_sid(&self) -> &str {
        &self.user_sid
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn dacl(&self) -> &str {
        &self.dacl
    }
    pub fn first_instance(&self) -> bool {
        self.first_instance
    }
    pub fn reject_remote(&self) -> bool {
        self.reject_remote
    }
    pub fn is_secure(&self) -> bool {
        self.first_instance
            && self.reject_remote
            && self.dacl.starts_with("D:P(A;;GRGW;;;")
            && self.dacl.ends_with(PIPE_DACL_SUFFIX)
            && !self.dacl.contains(";;;WD)")
            && valid_sid(&self.user_sid)
    }
}

fn valid_sid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("S-1-") else {
        return false;
    };
    let parts: Vec<_> = rest.split('-').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pub pid: u32,
    pub elevated: bool,
    pub high_integrity: bool,
    pub image: String,
    pub session_id: u32,
    pub file: FileIdentity,
    pub process_alive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub volume_serial: u64,
    pub file_id: u128,
    pub regular_file: bool,
    pub reparse: bool,
}

pub fn authenticate_helper(
    peer: &PeerIdentity,
    expected_pid: u32,
    expected_session: u32,
) -> Result<(), TransportError> {
    if expected_pid != 0
        && expected_session != 0
        && peer.pid == expected_pid
        && peer.elevated
        && peer.high_integrity
        && peer.image == HELPER_IMAGE_PATH
        && peer.session_id == expected_session
        && peer.process_alive
        && peer.file.regular_file
        && !peer.file.reparse
        && peer.file.volume_serial != 0
        && peer.file.file_id != 0
    {
        Ok(())
    } else {
        Err(TransportError::Authentication)
    }
}

pub fn authenticate_helper_continuity(
    initial: &PeerIdentity,
    current: &PeerIdentity,
) -> Result<(), TransportError> {
    if current.process_alive && current.pid == initial.pid && current.file == initial.file {
        authenticate_helper(current, initial.pid, initial.session_id)
    } else {
        Err(TransportError::Authentication)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogState {
    Armed,
    Disarmed,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogDecision {
    Wait,
    Abort,
    Disarmed,
}

/// Pure watchdog worker transition. Equality with the deadline is expired.
pub fn watchdog_worker_state(
    state: WatchdogState,
    deadline: Duration,
    now: Duration,
) -> WatchdogState {
    if state == WatchdogState::Armed && now >= deadline {
        WatchdogState::Expired
    } else {
        state
    }
}

/// Pure disarm transition. The worker and disarm path use the same boundary,
/// so a race at the deadline fails closed regardless of lock acquisition order.
pub fn watchdog_disarm_state(
    state: WatchdogState,
    deadline: Duration,
    now: Duration,
) -> WatchdogState {
    if state == WatchdogState::Armed && now < deadline {
        WatchdogState::Disarmed
    } else if state == WatchdogState::Armed || state == WatchdogState::Expired {
        WatchdogState::Expired
    } else {
        WatchdogState::Disarmed
    }
}

pub fn watchdog_decision(
    state: WatchdogState,
    deadline: Duration,
    now: Duration,
) -> WatchdogDecision {
    match watchdog_worker_state(state, deadline, now) {
        WatchdogState::Armed => WatchdogDecision::Wait,
        WatchdogState::Disarmed => WatchdogDecision::Disarmed,
        WatchdogState::Expired => WatchdogDecision::Abort,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlappedCancel {
    Succeeded,
    AlreadyComplete,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlappedOperation {
    Connect,
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlappedResult {
    Completed,
    OperationAborted,
    PipeClosed,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlappedDecision {
    Completed,
    Aborted,
    PipeClosed,
    AbortProcess,
}

/// Pure completion-barrier policy used by the native cancellation path.
/// `AlreadyComplete` models `ERROR_NOT_FOUND`; it is safe only when the event
/// was already signalled and the result is terminal.
pub fn overlapped_cancel_decision(
    operation: OverlappedOperation,
    cancel: OverlappedCancel,
    event_signalled: bool,
    result: OverlappedResult,
) -> OverlappedDecision {
    if matches!(cancel, OverlappedCancel::Failed)
        || !event_signalled
        || matches!(result, OverlappedResult::Other)
        || (matches!(result, OverlappedResult::PipeClosed)
            && !matches!(operation, OverlappedOperation::Read))
    {
        return OverlappedDecision::AbortProcess;
    }
    match result {
        OverlappedResult::Completed => OverlappedDecision::Completed,
        OverlappedResult::OperationAborted => OverlappedDecision::Aborted,
        OverlappedResult::PipeClosed => OverlappedDecision::PipeClosed,
        OverlappedResult::Other => unreachable!(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferedFrame {
    Empty,
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeClosedDecision {
    ObserveExit,
    RejectIncomplete,
}

pub fn pipe_closed_decision(frame: BufferedFrame) -> PipeClosedDecision {
    match frame {
        BufferedFrame::Complete => PipeClosedDecision::ObserveExit,
        BufferedFrame::Empty | BufferedFrame::Partial => PipeClosedDecision::RejectIncomplete,
    }
}

pub trait WindowsBoundary {
    fn now(&self) -> std::time::Duration;
    fn next(&mut self, deadline: std::time::Duration) -> Result<super::Event, TransportError>;
    fn send(&mut self, bytes: &[u8], deadline: std::time::Duration) -> Result<(), TransportError>;
    fn stop(&mut self);
    fn take_cleanup_error(&mut self) -> Option<TransportError> {
        None
    }
    fn request_committed(&self) -> bool {
        false
    }
    /// Create the explicit-DACL pipe, launch the fixed helper, and complete
    /// OS-backed peer authentication before hello/request bytes are read.
    fn start(&mut self, request_id: &RequestId) -> Result<(), TransportError>;
    /// Start using the single absolute authentication deadline. Implementors
    /// with overlapped Win32 I/O override this; fakes can use `start`.
    fn start_until(
        &mut self,
        request_id: &RequestId,
        _deadline: std::time::Duration,
    ) -> Result<(), TransportError> {
        self.start(request_id)
    }
}

struct IoAdapter<'a, B: WindowsBoundary> {
    boundary: &'a mut B,
    operation_deadline: Option<std::time::Duration>,
}
impl<B: WindowsBoundary> IoAdapter<'_, B> {
    fn start_until(
        &mut self,
        id: &RequestId,
        deadline: std::time::Duration,
    ) -> Result<(), TransportError> {
        let result = self.boundary.start_until(id, deadline);
        if result.is_ok() {
            self.operation_deadline = Some(self.now() + std::time::Duration::from_secs(30));
        }
        result
    }
    fn now(&self) -> std::time::Duration {
        self.boundary.now()
    }
}
impl<B: WindowsBoundary> super::ClientIo for IoAdapter<'_, B> {
    fn now(&self) -> std::time::Duration {
        self.boundary.now()
    }
    fn next(&mut self, deadline: std::time::Duration) -> Result<super::Event, TransportError> {
        self.boundary.next(deadline)
    }
    fn send(&mut self, bytes: &[u8], deadline: std::time::Duration) -> Result<(), TransportError> {
        self.boundary.send(bytes, deadline)
    }
    fn stop(&mut self) {
        self.boundary.stop()
    }
    fn operation_deadline(&self) -> Option<std::time::Duration> {
        self.operation_deadline
    }
}

pub struct WindowsClient<B: WindowsBoundary> {
    boundary: B,
}

impl<B: WindowsBoundary> WindowsClient<B> {
    pub fn new(boundary: B) -> Self {
        Self { boundary }
    }
    pub fn into_boundary(self) -> B {
        self.boundary
    }
    pub fn run(&mut self, request: Request) -> Result<Report, ClientError> {
        let mut io = IoAdapter {
            boundary: &mut self.boundary,
            operation_deadline: None,
        };
        let result = run_exchange(&mut io, request, |io, id, deadline| {
            io.start_until(id, deadline)
        });
        self.boundary.stop();
        let request_committed = self.boundary.request_committed();
        match self.boundary.take_cleanup_error() {
            None => result,
            Some(error) if request_committed => Err(ClientError::UnknownAfterSend(error)),
            Some(error) => match result {
                Err(ClientError::Cancelled) => Err(ClientError::Cancelled),
                _ => Err(ClientError::BeforeSend(error)),
            },
        }
    }
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::SystemWindowsBoundary;

#[cfg(windows)]
pub fn system() -> WindowsClient<SystemWindowsBoundary> {
    WindowsClient::new(SystemWindowsBoundary::system())
}
