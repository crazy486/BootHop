//! Authenticated Windows helper transport.
//!
//! The policy and trust decision functions in this module are portable and
//! are the only part exercised by host tests.  The Win32 session is compiled
//! on Windows, but is never constructed by tests or CI on this host.

use super::{GUI_IMAGE_PATH, HELPER_IMAGE_PATH};
use boothop_core::{Error, PlatformOperation};
use boothop_protocol::{MAX_BYTES, RequestId};
use std::time::{Duration, Instant};

pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\BootHop.";
pub const PIPE_MAX_BYTES: usize = MAX_BYTES;
pub const DEFAULT_AUTH_DEADLINE: Duration = Duration::from_secs(120);
pub const DEFAULT_OPERATION_DEADLINE: Duration = Duration::from_secs(30);
/// Explicit baseline ACL used by the named-pipe server. The GUI native
/// boundary adds the launching user's exact SID with `pipe_dacl_for_user_sid`;
/// SY and BA are the only other principals admitted. No default ACL is used.
pub const PIPE_DACL: &str = "D:P(A;;GRGW;;;SY)(A;;GRGW;;;BA)";

pub fn pipe_dacl_for_user_sid(sid: &str) -> Result<String, CliError> {
    let mut parts = sid.split('-');
    let valid = parts.next() == Some("S")
        && parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        && parts.all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if sid.len() > 184 || !valid {
        return Err(CliError::Invalid);
    }
    Ok(format!("D:P(A;;GRGW;;;{sid})(A;;GRGW;;;SY)(A;;GRGW;;;BA)"))
}

/// The native TOKEN_MANDATORY_LABEL is read from a byte buffer only after
/// this portable layout proof.  Offsets must be naturally aligned and every
/// pointer-sized field must remain inside the bytes returned by Win32.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenLabelLayout {
    pub label_offset: usize,
    pub sid_offset: usize,
    pub sid_length: usize,
    pub subauthority_count: u8,
}

pub fn validate_token_label_layout(
    storage_len: usize,
    return_length: usize,
    layout: TokenLabelLayout,
) -> Result<(), CliError> {
    const ALIGN: usize = std::mem::align_of::<usize>();
    let label_size = std::mem::size_of::<usize>() * 2;
    if return_length > storage_len
        || return_length < label_size
        || !layout.label_offset.is_multiple_of(ALIGN)
        || !layout
            .sid_offset
            .is_multiple_of(std::mem::align_of::<u32>())
        || layout.label_offset.checked_add(label_size).is_none()
        || layout.label_offset + label_size > return_length
        || layout.sid_offset < layout.label_offset + label_size
        || layout.sid_length < 8
        || layout.subauthority_count == 0
        || layout.sid_offset.checked_add(layout.sid_length).is_none()
        || layout.sid_offset + layout.sid_length > return_length
    {
        return Err(CliError::Invalid);
    }
    let expected_sid_len = 8usize
        .checked_add(usize::from(layout.subauthority_count) * 4)
        .ok_or(CliError::Invalid)?;
    if expected_sid_len != layout.sid_length {
        return Err(CliError::Invalid);
    }
    Ok(())
}

pub fn validate_sid_bytes(bytes: &[u8], subauthority_count: u8) -> Result<(), CliError> {
    let expected = 8usize
        .checked_add(usize::from(subauthority_count) * 4)
        .ok_or(CliError::Invalid)?;
    if bytes.len() != expected || bytes.first() != Some(&1) || bytes[1] != subauthority_count {
        return Err(CliError::Invalid);
    }
    if subauthority_count == 0 {
        return Err(CliError::Invalid);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlappedEvent {
    Pending,
    TimedOut,
    CancelIssued,
    CancelFailed,
    Completed,
    Aborted,
    AlreadyComplete,
    Closed,
}

/// Pure audit model for the native completion barrier. Closing is valid only
/// after a terminal completion observation, including cancellation races.
pub fn validate_overlapped_trace(trace: &[OverlappedEvent]) -> Result<(), CliError> {
    if trace.is_empty() || !matches!(trace[0], OverlappedEvent::Pending) {
        return Err(CliError::Invalid);
    }
    let close_count = trace
        .iter()
        .filter(|event| **event == OverlappedEvent::Closed)
        .count();
    if close_count != 1 || trace.last() != Some(&OverlappedEvent::Closed) {
        return Err(CliError::Invalid);
    }
    let close_at = trace.len() - 1;
    let terminal_at = trace[..close_at].iter().position(|event| {
        matches!(
            event,
            OverlappedEvent::Completed
                | OverlappedEvent::Aborted
                | OverlappedEvent::AlreadyComplete
        )
    });
    let Some(terminal_at) = terminal_at else {
        return Err(CliError::Invalid);
    };
    if trace[terminal_at + 1..close_at]
        .iter()
        .any(|event| *event != OverlappedEvent::Completed && *event != OverlappedEvent::Aborted)
    {
        return Err(CliError::Invalid);
    }
    if trace.contains(&OverlappedEvent::TimedOut)
        && !trace[..terminal_at].iter().any(|event| {
            matches!(
                event,
                OverlappedEvent::CancelIssued | OverlappedEvent::CancelFailed
            )
        })
    {
        return Err(CliError::Invalid);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperArgs {
    pub request_id: RequestId,
    pub gui_pid: u32,
}

impl HelperArgs {
    pub fn new(request_id: &str, gui_pid: u32) -> Result<Self, CliError> {
        if gui_pid == 0 {
            return Err(CliError::Invalid);
        }
        let request_id = RequestId::parse(request_id).map_err(|_| CliError::Invalid)?;
        Ok(Self {
            request_id,
            gui_pid,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliError {
    Invalid,
}

/// Parse argv excluding argv[0].  The order and spelling are part of the
/// helper's closed launch contract; no path, command, secret, or mode is
/// accepted from the caller.
pub fn parse_args(args: &[String]) -> Result<HelperArgs, CliError> {
    if args.len() != 3 || args[0] != "--version=2" {
        return Err(CliError::Invalid);
    }
    let id = args[1]
        .strip_prefix("--request-id=")
        .ok_or(CliError::Invalid)?;
    let pid = args[2]
        .strip_prefix("--gui-pid=")
        .ok_or(CliError::Invalid)?;
    if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError::Invalid);
    }
    // Reject non-canonical decimal forms so a command-shaped or alternate
    // representation cannot be smuggled through argument normalization.
    if pid.len() > 1 && pid.starts_with('0') {
        return Err(CliError::Invalid);
    }
    let gui_pid = pid.parse::<u32>().map_err(|_| CliError::Invalid)?;
    HelperArgs::new(id, gui_pid)
}

pub fn parse_args_os(args: &[std::ffi::OsString]) -> Result<HelperArgs, CliError> {
    let mut values = Vec::with_capacity(args.len());
    for arg in args {
        values.push(arg.to_str().ok_or(CliError::Invalid)?.to_owned());
    }
    parse_args(&values)
}

pub fn build_pipe_name(request_id: &RequestId) -> String {
    let mut name = String::with_capacity(PIPE_NAME_PREFIX.len() + 32);
    name.push_str(PIPE_NAME_PREFIX);
    name.push_str(request_id.as_str());
    name
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipePolicy<'a> {
    pub first_instance: bool,
    pub reject_remote: bool,
    pub dacl: &'a str,
}

impl<'a> PipePolicy<'a> {
    pub const fn secure() -> Self {
        Self {
            first_instance: true,
            reject_remote: true,
            dacl: PIPE_DACL,
        }
    }
}

pub fn validate_pipe_policy(policy: PipePolicy<'_>) -> Result<(), Error> {
    if policy.first_instance && policy.reject_remote && valid_pipe_dacl(policy.dacl) {
        Ok(())
    } else {
        Err(auth_error())
    }
}

fn valid_pipe_dacl(dacl: &str) -> bool {
    if dacl == PIPE_DACL {
        return true;
    }
    let Some(user) = dacl
        .strip_prefix("D:P(A;;GRGW;;;")
        .and_then(|value| value.strip_suffix(")(A;;GRGW;;;SY)(A;;GRGW;;;BA)"))
    else {
        return false;
    };
    pipe_dacl_for_user_sid(user).is_ok_and(|expected| expected == dacl)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipeServerSpec {
    pub request_id: RequestId,
    pub user_sid: String,
}

impl PipeServerSpec {
    pub fn new(request_id: RequestId, user_sid: &str) -> Result<Self, CliError> {
        RequestId::parse(request_id.as_str()).map_err(|_| CliError::Invalid)?;
        let dacl = pipe_dacl_for_user_sid(user_sid)?;
        if !valid_pipe_dacl(&dacl) {
            return Err(CliError::Invalid);
        }
        Ok(Self {
            request_id,
            user_sid: user_sid.to_owned(),
        })
    }
    pub fn name(&self) -> String {
        build_pipe_name(&self.request_id)
    }
    pub fn dacl(&self) -> Result<String, CliError> {
        pipe_dacl_for_user_sid(&self.user_sid)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenEvidence {
    pub elevated: bool,
    pub high_integrity: bool,
    pub user_sid: String,
    pub token_id: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageEvidence {
    pub canonical_path: String,
    pub reparse: bool,
    /// Stable identity captured from an opened file handle. Zero is invalid.
    pub file_id: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfEvidence {
    pub token: TokenEvidence,
    pub image: ImageEvidence,
    pub session_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthEvidence {
    pub pid: u32,
    pub token: TokenEvidence,
    pub image: ImageEvidence,
    pub session_id: u32,
}

/// Narrow OS-backed process/token/image/session seam. Implementations must
/// obtain image identity through opened process/file handles, not a caller
/// path or command line, and must retain a live process handle until the
/// continuity check returns.
pub trait PeerVerifier {
    fn inspect_self(&mut self) -> Result<SelfEvidence, Error>;
    fn inspect_peer(&mut self, pid: u32) -> Result<AuthEvidence, Error>;
    fn verify_peer_continuity(&mut self, pid: u32, evidence: &AuthEvidence) -> Result<(), Error>;
    fn inspect_self_until(&mut self, deadline: Instant) -> Result<SelfEvidence, Error> {
        auth_deadline_check(deadline)?;
        let result = self.inspect_self()?;
        auth_deadline_check(deadline)?;
        Ok(result)
    }
    fn inspect_peer_until(&mut self, pid: u32, deadline: Instant) -> Result<AuthEvidence, Error> {
        auth_deadline_check(deadline)?;
        let result = self.inspect_peer(pid)?;
        auth_deadline_check(deadline)?;
        Ok(result)
    }
    fn verify_peer_continuity_until(
        &mut self,
        pid: u32,
        evidence: &AuthEvidence,
        deadline: Instant,
    ) -> Result<(), Error> {
        auth_deadline_check(deadline)?;
        self.verify_peer_continuity(pid, evidence)?;
        auth_deadline_check(deadline)
    }
    fn release_peer_lease(&mut self) {}
}

fn auth_deadline_check(deadline: Instant) -> Result<(), Error> {
    deadline_remaining(deadline, Instant::now())
        .map(|_| ())
        .map_err(|_| auth_error())
}

fn valid_image(image: &ImageEvidence, expected: &str) -> bool {
    !image.reparse
        && image.file_id != 0
        && image.canonical_path == expected
        && !image.canonical_path.contains("..")
}

fn auth_error() -> Error {
    // Authentication failures intentionally expose no PID, SID, path, ID, or
    // token detail. The raw code is only the closed Win32 security class.
    Error::PlatformIo {
        operation: PlatformOperation::Security,
        raw_code: 5,
    }
}

pub fn authenticate_peer<V: PeerVerifier>(
    verifier: &mut V,
    args: &HelperArgs,
) -> Result<AuthEvidence, Error> {
    authenticate_peer_until(verifier, args, Instant::now() + DEFAULT_AUTH_DEADLINE)
}

pub fn authenticate_peer_until<V: PeerVerifier>(
    verifier: &mut V,
    args: &HelperArgs,
    deadline: Instant,
) -> Result<AuthEvidence, Error> {
    let self_evidence = verifier
        .inspect_self_until(deadline)
        .map_err(|_| auth_error())?;
    if !self_evidence.token.elevated
        || !self_evidence.token.high_integrity
        || pipe_dacl_for_user_sid(&self_evidence.token.user_sid).is_err()
        || self_evidence.token.token_id == 0
        || !valid_image(&self_evidence.image, HELPER_IMAGE_PATH)
        || self_evidence.session_id == 0
    {
        return Err(auth_error());
    }

    let peer = verifier
        .inspect_peer_until(args.gui_pid, deadline)
        .map_err(|_| auth_error())?;
    if peer.pid != args.gui_pid
        || peer.session_id != self_evidence.session_id
        || !valid_image(&peer.image, GUI_IMAGE_PATH)
        || pipe_dacl_for_user_sid(&peer.token.user_sid).is_err()
        || peer.token.token_id == 0
    {
        return Err(auth_error());
    }
    verifier
        .verify_peer_continuity_until(args.gui_pid, &peer, deadline)
        .map_err(|_| auth_error())?;
    Ok(peer)
}

/// Bind the OS-reported connected server PID to the launch argument before
/// any hello/request bytes are accepted.
pub fn authenticate_peer_on_connection<V: PeerVerifier>(
    verifier: &mut V,
    args: &HelperArgs,
    server_pid: u32,
) -> Result<(), Error> {
    authenticate_peer_on_connection_until(
        verifier,
        args,
        server_pid,
        Instant::now() + DEFAULT_AUTH_DEADLINE,
    )
}

pub fn authenticate_peer_on_connection_until<V: PeerVerifier>(
    verifier: &mut V,
    args: &HelperArgs,
    server_pid: u32,
    deadline: Instant,
) -> Result<(), Error> {
    auth_deadline_check(deadline)?;
    if server_pid != args.gui_pid {
        return Err(auth_error());
    }
    authenticate_peer_until(verifier, args, deadline).map(|_| ())
}

pub fn validate_request_id(expected: &RequestId, actual: &RequestId) -> Result<(), Error> {
    if expected == actual {
        Ok(())
    } else {
        Err(auth_error())
    }
}

pub fn deadline_remaining(deadline: Instant, now: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(now)
        .ok_or(Error::PlatformIo {
            operation: PlatformOperation::Ipc,
            raw_code: 1460,
        })
}

/// Exact one-shot framing boundary used by the native session. A session may
/// receive only one complete frame and cannot accept bytes after its declared
/// frame length.
pub trait PipeIo {
    fn receive_frame(&mut self, deadline: std::time::Instant) -> Result<Vec<u8>, Error>;
    fn send_frame(&mut self, bytes: &[u8], deadline: std::time::Instant) -> Result<(), Error>;
    fn close(&mut self) -> Result<(), Error>;
}

struct SessionAdapter<'a, I: PipeIo> {
    io: &'a mut I,
    deadline: Instant,
    before_send: Option<&'a mut dyn FnMut() -> Result<(), Error>>,
}

impl<I: PipeIo> crate::dispatch::SessionIo for SessionAdapter<'_, I> {
    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        self.io.receive_frame(self.deadline)
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if let Some(before_send) = self.before_send.as_mut() {
            before_send()?;
        }
        self.io.send_frame(bytes, self.deadline)
    }
}

/// Run a single authenticated session. Authentication happens before the
/// adapter is allowed to read request bytes, and the transport is closed once
/// after dispatch on every ordinary success or error path.
pub fn serve_authenticated_session<I, V, C, P>(
    io: &mut I,
    args: &HelperArgs,
    verifier: &mut V,
    acquire: impl FnOnce() -> Result<crate::windows::WindowsOperationGuard<C>, Error>,
    construct: impl FnOnce(&crate::windows::WindowsOperationGuard<C>) -> Result<P, Error>,
) -> Result<(), Error>
where
    I: PipeIo,
    V: PeerVerifier,
    C: crate::windows::OperationMutex,
    P: boothop_core::Platform,
{
    serve_authenticated_session_until(
        io,
        args,
        verifier,
        Instant::now() + DEFAULT_AUTH_DEADLINE,
        acquire,
        construct,
    )
}

pub fn serve_authenticated_session_until<I, V, C, P>(
    io: &mut I,
    args: &HelperArgs,
    verifier: &mut V,
    auth_deadline: Instant,
    acquire: impl FnOnce() -> Result<crate::windows::WindowsOperationGuard<C>, Error>,
    construct: impl FnOnce(&crate::windows::WindowsOperationGuard<C>) -> Result<P, Error>,
) -> Result<(), Error>
where
    I: PipeIo,
    V: PeerVerifier,
    C: crate::windows::OperationMutex,
    P: boothop_core::Platform,
{
    let result = match authenticate_peer_until(verifier, args, auth_deadline) {
        Err(error) => Err(error),
        Ok(evidence) => {
            let mut before_send = || {
                verifier
                    .verify_peer_continuity(args.gui_pid, &evidence)
                    .map_err(|_| auth_error())
            };
            let mut session = SessionAdapter {
                io,
                deadline: Instant::now() + DEFAULT_OPERATION_DEADLINE,
                before_send: Some(&mut before_send),
            };
            crate::dispatch::serve_windows_with_id(
                &mut session,
                &args.request_id,
                || Ok(()),
                acquire,
                construct,
            )
        }
    };
    verifier.release_peer_lease();
    let closed = io.close();
    result.and(closed)
}

pub fn validate_frame(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() < 4 || bytes.len() > PIPE_MAX_BYTES {
        return Err(Error::ResourceLimit);
    }
    let declared = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if declared > PIPE_MAX_BYTES - 4 || declared + 4 != bytes.len() {
        return Err(Error::UnsupportedFormat);
    }
    Ok(())
}

#[cfg(windows)]
#[allow(dead_code)]
mod native {
    use super::*;
    use crate::dispatch::SessionIo;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_TIMEOUT,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
        TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
        TokenElevation, TokenIntegrityLevel, TokenStatistics, TokenUser,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, GetFileInformationByHandle,
        GetFinalPathNameByHandleW, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::IO::{
        CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
        SetNamedPipeHandleState, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, GetProcessId, OpenProcess, OpenProcessToken,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    const ERROR_BROKEN_PIPE: i32 = 109;

    fn native_error(operation: PlatformOperation, raw_code: i32) -> Error {
        Error::PlatformIo {
            operation,
            raw_code,
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn auth_step(deadline: Instant) -> Result<(), Error> {
        auth_deadline_check(deadline)
    }

    /// The helper is a pipe client. The GUI owns the first-instance server and
    /// supplies the explicit ACL; this side still rejects a non-pipe handle
    /// and asks the server PID through the authenticated pipe boundary.
    pub struct SystemPipe {
        handle: HANDLE,
        closed: bool,
    }

    impl SystemPipe {
        pub fn connect(args: &HelperArgs, timeout_ms: u32) -> Result<Self, Error> {
            let deadline = Instant::now()
                + Duration::from_millis(u64::from(
                    timeout_ms.min(DEFAULT_AUTH_DEADLINE.as_millis() as u32),
                ));
            Self::connect_until(args, deadline)
        }

        pub fn connect_until(args: &HelperArgs, deadline: Instant) -> Result<Self, Error> {
            let name = wide(&build_pipe_name(&args.request_id));
            let timeout_ms = remaining_ms(deadline).map_err(|_| auth_error())?;
            if unsafe { WaitNamedPipeW(name.as_ptr(), timeout_ms) } == 0 {
                return Err(native_error(PlatformOperation::Ipc, unsafe {
                    GetLastError() as i32
                }));
            }
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return Err(native_error(PlatformOperation::Ipc, unsafe {
                    GetLastError() as i32
                }));
            }
            if let Err(error) = auth_deadline_check(deadline) {
                unsafe { CloseHandle(handle) };
                return Err(error);
            }
            let mode = PIPE_READMODE_BYTE | PIPE_WAIT;
            let ok = unsafe { SetNamedPipeHandleState(handle, &mode, null_mut(), null_mut()) };
            if ok == 0 {
                let code = unsafe { GetLastError() as i32 };
                unsafe { CloseHandle(handle) };
                return Err(native_error(PlatformOperation::Ipc, code));
            }
            if let Err(error) = auth_deadline_check(deadline) {
                unsafe { CloseHandle(handle) };
                return Err(error);
            }
            Ok(Self {
                handle,
                closed: false,
            })
        }

        pub fn server_pid(&self) -> Result<u32, Error> {
            let mut pid = 0;
            if unsafe { GetNamedPipeServerProcessId(self.handle, &mut pid) } == 0 {
                return Err(native_error(PlatformOperation::Process, unsafe {
                    GetLastError() as i32
                }));
            }
            if pid == 0 {
                return Err(native_error(PlatformOperation::Process, ERROR_BROKEN_PIPE));
            }
            Ok(pid)
        }
    }

    fn remaining_ms(deadline: Instant) -> Result<u32, Error> {
        let remaining = deadline_remaining(deadline, Instant::now())?;
        Ok(remaining.as_millis().clamp(1, u32::MAX as u128) as u32)
    }

    fn transfer(
        handle: HANDLE,
        buffer: &mut [u8],
        write: bool,
        deadline: Instant,
    ) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let _initial_ms = remaining_ms(deadline)?;
        let event = unsafe { CreateEventW(null_mut(), 1, 0, std::ptr::null()) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            return Err(native_error(PlatformOperation::Ipc, unsafe {
                GetLastError() as i32
            }));
        }
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };
        let mut transferred = 0;
        let ok = unsafe {
            if write {
                WriteFile(
                    handle,
                    buffer.as_ptr(),
                    buffer.len() as u32,
                    &mut transferred,
                    &mut overlapped,
                )
            } else {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut transferred,
                    &mut overlapped,
                )
            }
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_IO_PENDING {
                unsafe { CloseHandle(event) };
                return Err(native_error(PlatformOperation::Ipc, code as i32));
            }
            let wait_ms = match remaining_ms(deadline) {
                Ok(value) => value,
                Err(error) => {
                    let barrier = cancel_and_join(handle, &overlapped);
                    unsafe { CloseHandle(event) };
                    return Err(barrier.err().unwrap_or(error));
                }
            };
            if unsafe { GetOverlappedResultEx(handle, &overlapped, &mut transferred, wait_ms, 0) }
                == 0
            {
                let code = unsafe { GetLastError() };
                let barrier = cancel_and_join(handle, &overlapped);
                unsafe { CloseHandle(event) };
                barrier?;
                return Err(native_error(
                    PlatformOperation::Ipc,
                    if code == ERROR_TIMEOUT {
                        ERROR_TIMEOUT as i32
                    } else {
                        code as i32
                    },
                ));
            }
        }
        let _ = unsafe { CloseHandle(event) };
        Ok(transferred as usize)
    }

    /// Cancel and synchronously observe completion before the event,
    /// OVERLAPPED, or caller-owned buffer can leave scope.  NOT_FOUND is the
    /// documented already-complete race; an aborted completion is also a
    /// successful barrier, while unrelated completion errors remain visible.
    fn cancel_and_join(handle: HANDLE, overlapped: &OVERLAPPED) -> Result<(), Error> {
        let cancel_ok = unsafe { CancelIoEx(handle, overlapped) };
        let cancel_error = if cancel_ok == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        let mut transferred = 0;
        let completed = unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 1) };
        let completion_error = if completed == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if completed == 0
            && completion_error != ERROR_OPERATION_ABORTED
            && completion_error != ERROR_NOT_FOUND
        {
            return Err(native_error(
                PlatformOperation::Ipc,
                if cancel_error != 0 {
                    cancel_error as i32
                } else {
                    completion_error as i32
                },
            ));
        }
        Ok(())
    }

    impl SessionIo for SystemPipe {
        fn receive(&mut self) -> Result<Vec<u8>, Error> {
            self.receive_frame(Instant::now() + DEFAULT_OPERATION_DEADLINE)
        }
        fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
            self.send_frame(bytes, Instant::now() + DEFAULT_OPERATION_DEADLINE)
        }
    }

    impl PipeIo for SystemPipe {
        fn receive_frame(&mut self, deadline: std::time::Instant) -> Result<Vec<u8>, Error> {
            let mut prefix = [0u8; 4];
            let mut offset = 0;
            while offset < prefix.len() {
                let n = transfer(self.handle, &mut prefix[offset..], false, deadline)?;
                if n == 0 {
                    return Err(native_error(PlatformOperation::Ipc, ERROR_BROKEN_PIPE));
                }
                offset += n;
            }
            let size = u32::from_le_bytes(prefix) as usize;
            if size > PIPE_MAX_BYTES - 4 {
                return Err(Error::ResourceLimit);
            }
            let mut frame = vec![0; size + 4];
            frame[..4].copy_from_slice(&prefix);
            let mut offset = 0;
            while offset < size {
                let n = transfer(self.handle, &mut frame[4 + offset..], false, deadline)?;
                if n == 0 {
                    return Err(native_error(PlatformOperation::Ipc, ERROR_BROKEN_PIPE));
                }
                offset += n;
            }
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    self.handle,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            } == 0
            {
                return Err(native_error(PlatformOperation::Ipc, unsafe {
                    GetLastError() as i32
                }));
            }
            if available != 0 {
                return Err(Error::UnsupportedFormat);
            }
            validate_frame(&frame)?;
            Ok(frame)
        }
        fn send_frame(&mut self, bytes: &[u8], deadline: std::time::Instant) -> Result<(), Error> {
            validate_frame(bytes)?;
            let mut offset = 0;
            while offset < bytes.len() {
                let mut chunk = bytes[offset..].to_vec();
                let n = transfer(self.handle, &mut chunk, true, deadline)?;
                if n == 0 {
                    return Err(native_error(PlatformOperation::Ipc, ERROR_BROKEN_PIPE));
                }
                offset += n;
            }
            Ok(())
        }
        fn close(&mut self) -> Result<(), Error> {
            if !self.closed {
                self.closed = true;
                if unsafe { CloseHandle(self.handle) } == 0 {
                    return Err(native_error(PlatformOperation::Ipc, unsafe {
                        GetLastError() as i32
                    }));
                }
            }
            Ok(())
        }
    }

    impl Drop for SystemPipe {
        fn drop(&mut self) {
            let _ = self.close();
        }
    }

    /// Server-side constructor used by the authenticated local transport
    /// boundary. It is single-instance, rejects remote clients, and always
    /// receives an explicit DACL rather than inheriting the default ACL.
    #[allow(dead_code)]
    pub struct SystemPipeServer {
        handle: HANDLE,
    }

    impl SystemPipeServer {
        #[allow(dead_code)]
        pub fn create(spec: &PipeServerSpec) -> Result<Self, Error> {
            let name = wide(&spec.name());
            let dacl = spec.dacl().map_err(|_| auth_error())?;
            validate_pipe_policy(PipePolicy {
                first_instance: true,
                reject_remote: true,
                dacl: &dacl,
            })?;
            let dacl = wide(&dacl);
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
                return Err(native_error(PlatformOperation::Security, code as i32));
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    PIPE_MAX_BYTES as u32,
                    PIPE_MAX_BYTES as u32,
                    DEFAULT_AUTH_DEADLINE.as_millis() as u32,
                    &attributes,
                )
            };
            let create_error = unsafe { GetLastError() };
            unsafe { LocalFree(descriptor) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(native_error(PlatformOperation::Ipc, create_error as i32));
            }
            Ok(Self { handle })
        }

        pub fn accept(mut self, deadline: Instant) -> Result<SystemPipe, Error> {
            let event = unsafe { CreateEventW(null_mut(), 1, 0, std::ptr::null()) };
            if event.is_null() || event == INVALID_HANDLE_VALUE {
                return Err(native_error(PlatformOperation::Ipc, unsafe {
                    GetLastError() as i32
                }));
            }
            let mut overlapped = OVERLAPPED {
                hEvent: event,
                ..Default::default()
            };
            let connected = unsafe { ConnectNamedPipe(self.handle, &mut overlapped) };
            if connected == 0 {
                let code = unsafe { GetLastError() };
                if code != 535 && code != ERROR_IO_PENDING {
                    unsafe {
                        CloseHandle(event);
                    }
                    return Err(native_error(PlatformOperation::Ipc, code as i32));
                }
                if code == ERROR_IO_PENDING {
                    let mut transferred = 0;
                    let wait_ms = match remaining_ms(deadline) {
                        Ok(value) => value,
                        Err(error) => {
                            let barrier = cancel_and_join(self.handle, &overlapped);
                            unsafe {
                                CloseHandle(event);
                            }
                            return Err(barrier.err().unwrap_or(error));
                        }
                    };
                    if unsafe {
                        GetOverlappedResultEx(
                            self.handle,
                            &overlapped,
                            &mut transferred,
                            wait_ms,
                            0,
                        )
                    } == 0
                    {
                        let error = unsafe { GetLastError() };
                        let barrier = cancel_and_join(self.handle, &overlapped);
                        unsafe {
                            CloseHandle(event);
                        }
                        barrier?;
                        return Err(native_error(PlatformOperation::Ipc, error as i32));
                    }
                }
            }
            unsafe {
                CloseHandle(event);
            }
            let handle = self.handle;
            self.handle = null_mut();
            Ok(SystemPipe {
                handle,
                closed: false,
            })
        }
    }

    impl Drop for SystemPipeServer {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.handle) };
        }
    }

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub struct SystemPeerVerifier {
        // Retain the original opened peer process handle through the
        // continuity check so PID reuse cannot turn authentication into a
        // path-only check.
        peer_handle: Option<Handle>,
    }

    impl SystemPeerVerifier {
        pub fn new() -> Self {
            Self { peer_handle: None }
        }

        fn token(handle: HANDLE, deadline: Instant) -> Result<TokenEvidence, Error> {
            auth_step(deadline)?;
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0;
            if unsafe {
                GetTokenInformation(
                    handle,
                    TokenElevation,
                    (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut returned,
                )
            } == 0
            {
                return Err(auth_error());
            }
            auth_step(deadline)?;
            // Vec<u64> gives TOKEN_MANDATORY_LABEL its native alignment. The
            // returned length is authoritative; no pointer is dereferenced
            // until the complete structure and SID are proven in-bounds.
            let mut integrity = vec![0u64; 128];
            let integrity_ptr = integrity.as_mut_ptr().cast::<u8>();
            let integrity_bytes = integrity.len() * std::mem::size_of::<u64>();
            if unsafe {
                GetTokenInformation(
                    handle,
                    TokenIntegrityLevel,
                    integrity_ptr.cast(),
                    integrity_bytes as u32,
                    &mut returned,
                )
            } == 0
            {
                return Err(auth_error());
            }
            auth_step(deadline)?;
            let label_size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>();
            if (returned as usize) > integrity_bytes
                || (returned as usize) < label_size
                || !(integrity_ptr as usize)
                    .is_multiple_of(std::mem::align_of::<TOKEN_MANDATORY_LABEL>())
            {
                return Err(auth_error());
            }
            let label = unsafe { &*(integrity_ptr.cast::<TOKEN_MANDATORY_LABEL>()) };
            let sid = label.Label.Sid;
            if sid.is_null() {
                return Err(auth_error());
            }
            let base = integrity_ptr as usize;
            let sid_value = sid as usize;
            let sid_offset = sid_value.checked_sub(base).ok_or_else(auth_error)?;
            if !sid_offset.is_multiple_of(std::mem::align_of::<u32>())
                || sid_offset >= returned as usize
                || sid_offset >= integrity_bytes
                || sid_offset.checked_add(8).is_none()
                || sid_offset + 8 > returned as usize
                || sid_offset + 8 > integrity_bytes
            {
                return Err(auth_error());
            }
            if unsafe { IsValidSid(sid) == 0 } {
                return Err(auth_error());
            }
            let sid_len = unsafe { GetLengthSid(sid) as usize };
            let count = unsafe { GetSidSubAuthorityCount(sid) };
            if sid_len < 8
                || count.is_null()
                || sid_offset.checked_add(sid_len).is_none()
                || sid_offset + sid_len > returned as usize
                || sid_offset + sid_len > integrity_bytes
                || unsafe { *count == 0 }
            {
                return Err(auth_error());
            }
            let count_value = unsafe { *count };
            if validate_token_label_layout(
                integrity_bytes,
                returned as usize,
                TokenLabelLayout {
                    label_offset: 0,
                    sid_offset,
                    sid_length: sid_len,
                    subauthority_count: count_value,
                },
            )
            .is_err()
            {
                return Err(auth_error());
            }
            let sid_bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_len) };
            validate_sid_bytes(sid_bytes, count_value).map_err(|_| auth_error())?;
            let last_index = u32::from(count_value) - 1;
            let last_offset = 8usize + (last_index as usize) * 4;
            if last_offset + 4 > sid_len {
                return Err(auth_error());
            }
            let last = unsafe { GetSidSubAuthority(sid, last_index) };
            if last.is_null() {
                return Err(auth_error());
            }
            let high = unsafe { *last } >= SECURITY_MANDATORY_HIGH_RID as u32;
            let mut user_len = 0;
            let mut user = vec![0u64; 128];
            auth_step(deadline)?;
            if unsafe {
                GetTokenInformation(
                    handle,
                    TokenUser,
                    user.as_mut_ptr().cast(),
                    (user.len() * std::mem::size_of::<u64>()) as u32,
                    &mut user_len,
                )
            } == 0
                || (user_len as usize) > user.len() * std::mem::size_of::<u64>()
                || (user_len as usize) < std::mem::size_of::<TOKEN_USER>()
            {
                return Err(auth_error());
            }
            auth_step(deadline)?;
            let user_info = unsafe { &*(user.as_ptr().cast::<TOKEN_USER>()) };
            let user_sid_ptr = user_info.User.Sid;
            let user_base = user.as_ptr() as usize;
            let user_sid_value = user_sid_ptr as usize;
            let user_sid_offset = user_sid_value
                .checked_sub(user_base)
                .ok_or_else(auth_error)?;
            let user_sid_len = if user_sid_ptr.is_null()
                || user_sid_offset >= user_len as usize
                || user_sid_offset < std::mem::size_of::<TOKEN_USER>()
                || user_sid_offset % std::mem::align_of::<u32>() != 0
                || user_sid_offset.checked_add(8).is_none()
                || user_sid_offset + 8 > user_len as usize
            {
                return Err(auth_error());
            } else {
                if unsafe { IsValidSid(user_sid_ptr) == 0 } {
                    return Err(auth_error());
                }
                unsafe { GetLengthSid(user_sid_ptr) as usize }
            };
            let user_count_ptr = unsafe { GetSidSubAuthorityCount(user_sid_ptr) };
            if user_sid_len < 8
                || user_count_ptr.is_null()
                || user_sid_offset.checked_add(user_sid_len).is_none()
                || user_sid_offset + user_sid_len > user_len as usize
                || unsafe { *user_count_ptr == 0 }
            {
                return Err(auth_error());
            }
            let user_count = unsafe { *user_count_ptr };
            let user_expected_len = 8usize + usize::from(user_count) * 4;
            if user_sid_len != user_expected_len {
                return Err(auth_error());
            }
            let user_sid_bytes =
                unsafe { std::slice::from_raw_parts(user_sid_ptr.cast::<u8>(), user_sid_len) };
            validate_sid_bytes(user_sid_bytes, user_count).map_err(|_| auth_error())?;
            let mut sid_string = std::ptr::null_mut();
            if unsafe { ConvertSidToStringSidW(user_sid_ptr, &mut sid_string) } == 0
                || sid_string.is_null()
            {
                return Err(auth_error());
            }
            let user_sid = unsafe {
                let mut len = 0usize;
                while len <= 184 && *sid_string.add(len) != 0 {
                    len += 1;
                }
                if len > 184 {
                    let free_error = windows_sys::Win32::Foundation::GetLastError();
                    let _ = LocalFree(sid_string.cast());
                    let _ = free_error;
                    return Err(auth_error());
                }
                let value = String::from_utf16(std::slice::from_raw_parts(sid_string, len));
                let local_error = windows_sys::Win32::Foundation::GetLastError();
                let _ = LocalFree(sid_string.cast());
                let _ = local_error;
                value.map_err(|_| auth_error())?
            };
            let mut stats = TOKEN_STATISTICS::default();
            let mut stats_len = 0;
            auth_step(deadline)?;
            if unsafe {
                GetTokenInformation(
                    handle,
                    TokenStatistics,
                    (&mut stats as *mut TOKEN_STATISTICS).cast(),
                    std::mem::size_of::<TOKEN_STATISTICS>() as u32,
                    &mut stats_len,
                )
            } == 0
            {
                return Err(auth_error());
            }
            auth_step(deadline)?;
            let token_id = (u128::from(stats.TokenId.HighPart as u32) << 32)
                | u128::from(stats.TokenId.LowPart);
            Ok(TokenEvidence {
                elevated: elevation.TokenIsElevated != 0,
                high_integrity: high,
                user_sid,
                token_id,
            })
        }

        fn process(pid: u32, deadline: Instant) -> Result<(Handle, AuthEvidence), Error> {
            auth_step(deadline)?;
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    pid,
                )
            };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(auth_error());
            }
            let handle = Handle(handle);
            auth_step(deadline)?;
            let mut token = HANDLE::default();
            auth_step(deadline)?;
            if unsafe { OpenProcessToken(handle.0, TOKEN_QUERY, &mut token) } == 0 {
                return Err(auth_error());
            }
            let token = Handle(token);
            auth_step(deadline)?;
            let evidence = AuthEvidence {
                pid,
                token: Self::token(token.0, deadline)?,
                image: image(handle.0, GUI_IMAGE_PATH, deadline)?,
                session_id: session(pid, deadline)?,
            };
            Ok((handle, evidence))
        }
    }

    fn session(pid: u32, deadline: Instant) -> Result<u32, Error> {
        auth_step(deadline)?;
        let mut value = 0;
        if unsafe { ProcessIdToSessionId(pid, &mut value) } == 0 || value == 0 {
            return Err(auth_error());
        }
        auth_step(deadline)?;
        Ok(value)
    }

    fn image(process: HANDLE, expected: &str, deadline: Instant) -> Result<ImageEvidence, Error> {
        auth_step(deadline)?;
        let mut raw = vec![0u16; 32_768];
        let mut length = raw.len() as u32;
        if unsafe {
            windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
                process,
                0,
                raw.as_mut_ptr(),
                &mut length,
            )
        } == 0
        {
            return Err(auth_error());
        }
        auth_step(deadline)?;
        raw.truncate(length as usize);
        let reported = String::from_utf16(&raw).map_err(|_| auth_error())?;
        let reported = reported.strip_prefix(r"\\?\").unwrap_or(&reported);
        if reported != expected || reported.contains("..") {
            return Err(auth_error());
        }
        let path = wide(expected);
        let file = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if file.is_null() || file == INVALID_HANDLE_VALUE {
            return Err(auth_error());
        }
        let file = Handle(file);
        auth_step(deadline)?;
        let mut normalized = vec![0u16; 32_768];
        let count = unsafe {
            GetFinalPathNameByHandleW(
                file.0,
                normalized.as_mut_ptr(),
                normalized.len() as u32,
                FILE_NAME_NORMALIZED,
            )
        };
        if count == 0 || count as usize >= normalized.len() {
            return Err(auth_error());
        }
        auth_step(deadline)?;
        normalized.truncate(count as usize);
        let mut info = BY_HANDLE_FILE_INFORMATION {
            dwFileAttributes: 0,
            ftCreationTime: Default::default(),
            ftLastAccessTime: Default::default(),
            ftLastWriteTime: Default::default(),
            dwVolumeSerialNumber: 0,
            nFileSizeHigh: 0,
            nFileSizeLow: 0,
            nNumberOfLinks: 0,
            nFileIndexHigh: 0,
            nFileIndexLow: 0,
        };
        if unsafe { GetFileInformationByHandle(file.0, &mut info) } == 0 {
            return Err(auth_error());
        }
        auth_step(deadline)?;
        let canonical = String::from_utf16(&normalized).map_err(|_| auth_error())?;
        let canonical = canonical
            .strip_prefix(r"\\?\")
            .unwrap_or(&canonical)
            .to_owned();
        Ok(ImageEvidence {
            canonical_path: canonical,
            reparse: info.dwFileAttributes & 0x400 != 0,
            file_id: (u128::from(info.dwVolumeSerialNumber) << 64)
                | (u128::from(info.nFileIndexHigh) << 32)
                | u128::from(info.nFileIndexLow),
        })
    }

    impl PeerVerifier for SystemPeerVerifier {
        fn inspect_self(&mut self) -> Result<SelfEvidence, Error> {
            self.inspect_self_until(Instant::now() + DEFAULT_AUTH_DEADLINE)
        }

        fn inspect_self_until(&mut self, deadline: Instant) -> Result<SelfEvidence, Error> {
            let process = unsafe { GetCurrentProcess() };
            let mut token = HANDLE::default();
            auth_step(deadline)?;
            if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
                return Err(auth_error());
            }
            let token_handle = Handle(token);
            auth_step(deadline)?;
            Ok(SelfEvidence {
                token: Self::token(token_handle.0, deadline)?,
                image: image(process, HELPER_IMAGE_PATH, deadline)?,
                session_id: session(unsafe { GetCurrentProcessId() }, deadline)?,
            })
        }

        fn inspect_peer(&mut self, pid: u32) -> Result<AuthEvidence, Error> {
            self.inspect_peer_until(pid, Instant::now() + DEFAULT_AUTH_DEADLINE)
        }

        fn inspect_peer_until(
            &mut self,
            pid: u32,
            deadline: Instant,
        ) -> Result<AuthEvidence, Error> {
            let (handle, evidence) = Self::process(pid, deadline)?;
            self.peer_handle = Some(handle);
            Ok(evidence)
        }

        fn verify_peer_continuity(
            &mut self,
            pid: u32,
            evidence: &AuthEvidence,
        ) -> Result<(), Error> {
            self.verify_peer_continuity_until(pid, evidence, Instant::now() + DEFAULT_AUTH_DEADLINE)
        }

        fn verify_peer_continuity_until(
            &mut self,
            pid: u32,
            evidence: &AuthEvidence,
            deadline: Instant,
        ) -> Result<(), Error> {
            if self.peer_handle.is_none() {
                return Err(auth_error());
            }
            let retained = self.peer_handle.as_ref().ok_or_else(auth_error)?;
            auth_step(deadline)?;
            if unsafe { GetProcessId(retained.0) } != pid {
                return Err(auth_error());
            }
            let liveness = unsafe { WaitForSingleObject(retained.0, 0) };
            if liveness == WAIT_FAILED {
                return Err(native_error(PlatformOperation::Process, unsafe {
                    GetLastError() as i32
                }));
            }
            if liveness != WAIT_TIMEOUT {
                return Err(auth_error());
            }
            auth_step(deadline)?;
            let (_, current) = Self::process(pid, deadline)?;
            auth_step(deadline)?;
            if current == *evidence {
                Ok(())
            } else {
                Err(auth_error())
            }
        }

        fn release_peer_lease(&mut self) {
            self.peer_handle = None;
        }
    }

    pub fn run(args: HelperArgs) -> Result<(), Error> {
        let auth_deadline = Instant::now() + DEFAULT_AUTH_DEADLINE;
        let mut io = SystemPipe::connect_until(&args, auth_deadline)?;
        auth_step(auth_deadline)?;
        if io.server_pid()? != args.gui_pid {
            return Err(auth_error());
        }
        auth_step(auth_deadline)?;
        let mut verifier = SystemPeerVerifier::new();
        serve_authenticated_session_until(
            &mut io,
            &args,
            &mut verifier,
            auth_deadline,
            || {
                crate::windows::WindowsOperationGuard::acquire(
                    crate::windows::lock::native::SystemOperationMutex::default(),
                )
            },
            |_| {
                // SAFETY: this closure runs only after self/peer authentication
                // and after the helper-owned operation mutex is acquired; the
                // guard remains alive until the terminal response send returns.
                unsafe { boothop_platform::windows::production_after_operation_guard() }
            },
        )
    }
}

#[cfg(windows)]
pub fn run(args: HelperArgs) -> Result<(), Error> {
    native::run(args)
}
