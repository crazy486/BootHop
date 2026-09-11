use boothop_core::{Error, Report, Request};
use boothop_helper::protocol::{self, MAX_BYTES};
use std::time::Duration;
#[cfg(target_os = "linux")]
pub mod linux;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnSpec {
    pub program: &'static str,
    pub args: Vec<&'static str>,
    /// Entire environment, not additions to an inherited environment.
    pub environment: Vec<(&'static str, &'static str)>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Launch,
    Io,
    Timeout,
    Exit,
    Protocol,
    ResourceLimit,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    Cancelled,
    AuthorizationOrLaunchFailed,
    BeforeSend(TransportError),
    /// The helper may have set BootNext or accepted reboot. Never retry automatically.
    UnknownAfterSend(TransportError),
    Domain(Error),
}
pub enum Event {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}
/// Injectable monotonic clock/process/pipe boundary.
/// send writes all bytes and closes stdin. An Err MUST mean the request was
/// not completely written; after complete delivery it MUST return Ok, even if
/// subsequent cleanup fails. The helper requires a complete frame and EOF.
/// next drains both streams before Exit.
pub trait Boundary {
    fn now(&self) -> Duration;
    fn spawn(&mut self, spec: &SpawnSpec) -> Result<(), TransportError>;
    fn next(&mut self, deadline: Duration) -> Result<Event, TransportError>;
    fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), TransportError>;
    fn stop(&mut self);
}
pub struct HelperClient<B: Boundary> {
    boundary: B,
}
impl<B: Boundary> HelperClient<B> {
    pub fn new(boundary: B) -> Self {
        Self { boundary }
    }
    pub fn into_boundary(self) -> B {
        self.boundary
    }
    pub fn run(&mut self, request: Request) -> Result<Report, ClientError> {
        let result = self.run_once(request);
        self.boundary.stop();
        result
    }
    fn run_once(&mut self, request: Request) -> Result<Report, ClientError> {
        let request = protocol::encode_request(request)
            .map_err(|_| ClientError::BeforeSend(TransportError::Protocol))?;
        let hello_deadline = self.boundary.now() + Duration::from_secs(120);
        let spec = SpawnSpec {
            program: "/usr/bin/pkexec",
            args: vec![
                "--disable-internal-agent",
                "/usr/lib/boothop/boothop-helper",
            ],
            environment: vec![("LC_ALL", "C")],
        };
        self.boundary
            .spawn(&spec)
            .map_err(ClientError::BeforeSend)?;
        let mut used = 0;
        let mut stdout = Vec::new();
        loop {
            let event = self
                .boundary
                .next(hello_deadline)
                .map_err(ClientError::BeforeSend)?;
            if self.boundary.now() > hello_deadline {
                return Err(ClientError::BeforeSend(TransportError::Timeout));
            }
            match event {
                Event::Exit(126) => return Err(ClientError::Cancelled),
                Event::Exit(127) => return Err(ClientError::AuthorizationOrLaunchFailed),
                Event::Exit(_) => return Err(ClientError::BeforeSend(TransportError::Exit)),
                event => collect(event, &mut used, &mut stdout).map_err(ClientError::BeforeSend)?,
            }
            if complete(&stdout).map_err(ClientError::BeforeSend)? {
                protocol::decode_hello(&stdout)
                    .map_err(|_| ClientError::BeforeSend(TransportError::Protocol))?;
                break;
            }
        }
        let deadline = self.boundary.now() + Duration::from_secs(30);
        // send acknowledges complete delivery; its error contract guarantees an
        // incomplete frame, which the one-shot helper cannot execute.
        self.boundary
            .send(&request, deadline)
            .map_err(ClientError::BeforeSend)?;
        stdout.clear();
        loop {
            let event = self
                .boundary
                .next(deadline)
                .map_err(ClientError::UnknownAfterSend)?;
            if self.boundary.now() > deadline {
                return Err(ClientError::UnknownAfterSend(TransportError::Timeout));
            }
            match event {
                Event::Exit(0) => {
                    return protocol::decode_response(&stdout)
                        .map_err(|_| ClientError::UnknownAfterSend(TransportError::Protocol))?
                        .map_err(ClientError::Domain);
                }
                Event::Exit(_) => return Err(ClientError::UnknownAfterSend(TransportError::Exit)),
                event => {
                    collect(event, &mut used, &mut stdout).map_err(ClientError::UnknownAfterSend)?
                }
            }
            complete(&stdout).map_err(ClientError::UnknownAfterSend)?;
        }
    }
}
fn collect(event: Event, used: &mut usize, stdout: &mut Vec<u8>) -> Result<(), TransportError> {
    let bytes = match &event {
        Event::Stdout(b) | Event::Stderr(b) => b,
        Event::Exit(_) => unreachable!(),
    };
    if bytes.len() > MAX_BYTES.saturating_sub(*used) {
        return Err(TransportError::ResourceLimit);
    }
    *used += bytes.len();
    if matches!(event, Event::Stdout(_)) {
        stdout.extend_from_slice(bytes);
    }
    Ok(())
}
fn complete(bytes: &[u8]) -> Result<bool, TransportError> {
    if bytes.len() < 4 {
        return Ok(false);
    }
    let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if length > MAX_BYTES - 4 {
        return Err(TransportError::ResourceLimit);
    }
    if bytes.len() > length + 4 {
        return Err(TransportError::Protocol);
    }
    Ok(bytes.len() == length + 4)
}
