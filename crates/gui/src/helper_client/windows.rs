//! Windows GUI-to-helper transport boundary.
//!
//! The semantic request/response exchange is shared with the Linux client;
//! this module owns only the fixed Windows launch and named-pipe session.
//! Native calls live in `native` and are compiled only for Windows. Tests use
//! the `WindowsBoundary` trait and never create a pipe or display UAC.

use super::{ClientError, TransportError, run_exchange};
use boothop_core::{Report, Request};
use boothop_protocol::RequestId;

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
}

pub fn authenticate_helper(
    peer: &PeerIdentity,
    expected_pid: u32,
    expected_session: u32,
) -> Result<(), TransportError> {
    if peer.pid == expected_pid
        && peer.elevated
        && peer.high_integrity
        && peer.image == HELPER_IMAGE_PATH
        && peer.session_id == expected_session
    {
        Ok(())
    } else {
        Err(TransportError::Authentication)
    }
}

pub trait WindowsBoundary {
    fn now(&self) -> std::time::Duration;
    fn next(&mut self, deadline: std::time::Duration) -> Result<super::Event, TransportError>;
    fn send(&mut self, bytes: &[u8], deadline: std::time::Duration) -> Result<(), TransportError>;
    fn stop(&mut self);
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

struct IoAdapter<'a, B: WindowsBoundary>(&'a mut B);
impl<B: WindowsBoundary> IoAdapter<'_, B> {
    fn start_until(
        &mut self,
        id: &RequestId,
        deadline: std::time::Duration,
    ) -> Result<(), TransportError> {
        self.0.start_until(id, deadline)
    }
    fn now(&self) -> std::time::Duration {
        self.0.now()
    }
}
impl<B: WindowsBoundary> super::ClientIo for IoAdapter<'_, B> {
    fn now(&self) -> std::time::Duration {
        self.0.now()
    }
    fn next(&mut self, deadline: std::time::Duration) -> Result<super::Event, TransportError> {
        self.0.next(deadline)
    }
    fn send(&mut self, bytes: &[u8], deadline: std::time::Duration) -> Result<(), TransportError> {
        self.0.send(bytes, deadline)
    }
    fn stop(&mut self) {
        self.0.stop()
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
        let mut io = IoAdapter(&mut self.boundary);
        let result = run_exchange(&mut io, request, |io, id| {
            io.start_until(id, io.now() + std::time::Duration::from_secs(120))
        });
        self.boundary.stop();
        result
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
