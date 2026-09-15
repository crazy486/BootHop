//! Authenticated Windows helper transport.
//!
//! The policy and trust decision functions in this module are portable and
//! are the only part exercised by host tests.  The Win32 session is compiled
//! on Windows, but is never constructed by tests or CI on this host.

use super::{GUI_IMAGE_PATH, HELPER_IMAGE_PATH};
use boothop_core::{Error, PlatformOperation};
use boothop_protocol::{MAX_BYTES, RequestId};
use std::time::Duration;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    if policy.first_instance && policy.reject_remote && policy.dacl == PIPE_DACL {
        Ok(())
    } else {
        Err(auth_error())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenEvidence {
    pub elevated: bool,
    pub high_integrity: bool,
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
) -> Result<(), Error> {
    let self_evidence = verifier.inspect_self().map_err(|_| auth_error())?;
    if !self_evidence.token.elevated
        || !self_evidence.token.high_integrity
        || !valid_image(&self_evidence.image, HELPER_IMAGE_PATH)
        || self_evidence.session_id == 0
    {
        return Err(auth_error());
    }

    let peer = verifier
        .inspect_peer(args.gui_pid)
        .map_err(|_| auth_error())?;
    if peer.pid != args.gui_pid
        || peer.session_id != self_evidence.session_id
        || !valid_image(&peer.image, GUI_IMAGE_PATH)
    {
        return Err(auth_error());
    }
    verifier
        .verify_peer_continuity(args.gui_pid, &peer)
        .map_err(|_| auth_error())
}

/// Bind the OS-reported connected server PID to the launch argument before
/// any hello/request bytes are accepted.
pub fn authenticate_peer_on_connection<V: PeerVerifier>(
    verifier: &mut V,
    args: &HelperArgs,
    server_pid: u32,
) -> Result<(), Error> {
    if server_pid != args.gui_pid {
        return Err(auth_error());
    }
    authenticate_peer(verifier, args)
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
}

impl<I: PipeIo> crate::dispatch::SessionIo for SessionAdapter<'_, I> {
    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        self.io
            .receive_frame(std::time::Instant::now() + DEFAULT_OPERATION_DEADLINE)
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.io.send_frame(
            bytes,
            std::time::Instant::now() + DEFAULT_OPERATION_DEADLINE,
        )
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
    let result = {
        let mut session = SessionAdapter { io };
        crate::dispatch::serve_windows(
            &mut session,
            || authenticate_peer(verifier, args),
            acquire,
            construct,
        )
    };
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
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_ELEVATION,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenElevation, TokenIntegrityLevel,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, GetFileInformationByHandle,
        GetFinalPathNameByHandleW, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
        SetNamedPipeHandleState, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
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

    /// The helper is a pipe client. The GUI owns the first-instance server and
    /// supplies the explicit ACL; this side still rejects a non-pipe handle
    /// and asks the server PID through the authenticated pipe boundary.
    pub struct SystemPipe {
        handle: HANDLE,
        closed: bool,
    }

    impl SystemPipe {
        pub fn connect(args: &HelperArgs, timeout_ms: u32) -> Result<Self, Error> {
            let name = wide(&build_pipe_name(&args.request_id));
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
                    FILE_ATTRIBUTE_NORMAL,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return Err(native_error(PlatformOperation::Ipc, unsafe {
                    GetLastError() as i32
                }));
            }
            let mode = PIPE_READMODE_BYTE | PIPE_WAIT;
            let ok = unsafe { SetNamedPipeHandleState(handle, &mode, null_mut(), null_mut()) };
            if ok == 0 {
                let code = unsafe { GetLastError() as i32 };
                unsafe { CloseHandle(handle) };
                return Err(native_error(PlatformOperation::Ipc, code));
            }
            let _ = timeout_ms; // The GUI server applies the connect deadline.
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

    impl SessionIo for SystemPipe {
        fn receive(&mut self) -> Result<Vec<u8>, Error> {
            let mut prefix = [0u8; 4];
            let mut read = 0;
            let ok =
                unsafe { ReadFile(self.handle, prefix.as_mut_ptr(), 4, &mut read, null_mut()) };
            if ok == 0 || read != 4 {
                return Err(native_error(PlatformOperation::Ipc, unsafe {
                    GetLastError() as i32
                }));
            }
            let size = u32::from_le_bytes(prefix) as usize;
            if size > PIPE_MAX_BYTES - 4 {
                return Err(Error::ResourceLimit);
            }
            let mut frame = vec![0; size + 4];
            frame[..4].copy_from_slice(&prefix);
            let mut offset = 0;
            while offset < size {
                let mut n = 0;
                let ok = unsafe {
                    ReadFile(
                        self.handle,
                        frame[4 + offset..].as_mut_ptr(),
                        (size - offset) as u32,
                        &mut n,
                        null_mut(),
                    )
                };
                if ok == 0 || n == 0 {
                    return Err(native_error(PlatformOperation::Ipc, unsafe {
                        GetLastError() as i32
                    }));
                }
                offset += n as usize;
            }
            // A one-shot endpoint rejects a second frame already queued on
            // the connection; it never silently executes only the prefix.
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

        fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
            validate_frame(bytes)?;
            let mut written = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut written,
                    null_mut(),
                )
            };
            if ok == 0 || written as usize != bytes.len() {
                return Err(native_error(PlatformOperation::Ipc, unsafe {
                    GetLastError() as i32
                }));
            }
            Ok(())
        }
    }

    impl PipeIo for SystemPipe {
        fn receive_frame(&mut self, _: std::time::Instant) -> Result<Vec<u8>, Error> {
            self.receive()
        }
        fn send_frame(&mut self, bytes: &[u8], _: std::time::Instant) -> Result<(), Error> {
            self.send(bytes)
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
        pub fn create(name: &str, dacl: &str) -> Result<Self, Error> {
            let name = wide(name);
            let dacl = wide(dacl);
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    dacl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(native_error(PlatformOperation::Security, unsafe {
                    GetLastError() as i32
                }));
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    PIPE_MAX_BYTES as u32,
                    PIPE_MAX_BYTES as u32,
                    DEFAULT_AUTH_DEADLINE.as_millis() as u32,
                    &attributes,
                )
            };
            unsafe { LocalFree(descriptor) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(native_error(PlatformOperation::Ipc, unsafe {
                    GetLastError() as i32
                }));
            }
            Ok(Self { handle })
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

        fn token(handle: HANDLE) -> Result<TokenEvidence, Error> {
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
            let mut integrity = [0u8; 1024];
            if unsafe {
                GetTokenInformation(
                    handle,
                    TokenIntegrityLevel,
                    integrity.as_mut_ptr().cast(),
                    integrity.len() as u32,
                    &mut returned,
                )
            } == 0
            {
                return Err(auth_error());
            }
            let label = unsafe { &*(integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
            let count = unsafe { GetSidSubAuthorityCount(label.Label.Sid) };
            if label.Label.Sid.is_null() || count.is_null() || unsafe { *count == 0 } {
                return Err(auth_error());
            }
            let last = unsafe { GetSidSubAuthority(label.Label.Sid, u32::from(*count) - 1) };
            if last.is_null() {
                return Err(auth_error());
            }
            let high = unsafe { *last } >= SECURITY_MANDATORY_HIGH_RID as u32;
            Ok(TokenEvidence {
                elevated: elevation.TokenIsElevated != 0,
                high_integrity: high,
            })
        }

        fn process(pid: u32) -> Result<(Handle, AuthEvidence), Error> {
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(auth_error());
            }
            let handle = Handle(handle);
            let mut token = HANDLE::default();
            if unsafe { OpenProcessToken(handle.0, TOKEN_QUERY, &mut token) } == 0 {
                return Err(auth_error());
            }
            let token = Handle(token);
            let evidence = AuthEvidence {
                pid,
                token: Self::token(token.0)?,
                image: image(handle.0)?,
                session_id: session(pid)?,
            };
            Ok((handle, evidence))
        }
    }

    fn session(pid: u32) -> Result<u32, Error> {
        let mut value = 0;
        if unsafe { ProcessIdToSessionId(pid, &mut value) } == 0 || value == 0 {
            return Err(auth_error());
        }
        Ok(value)
    }

    fn image(process: HANDLE) -> Result<ImageEvidence, Error> {
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
        raw.truncate(length as usize);
        let path = raw;
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
            let process = unsafe { GetCurrentProcess() };
            let mut token = HANDLE::default();
            if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
                return Err(auth_error());
            }
            let token_handle = Handle(token);
            Ok(SelfEvidence {
                token: Self::token(token_handle.0)?,
                image: image(process)?,
                session_id: session(unsafe { GetCurrentProcessId() })?,
            })
        }

        fn inspect_peer(&mut self, pid: u32) -> Result<AuthEvidence, Error> {
            let (handle, evidence) = Self::process(pid)?;
            self.peer_handle = Some(handle);
            Ok(evidence)
        }

        fn verify_peer_continuity(
            &mut self,
            pid: u32,
            evidence: &AuthEvidence,
        ) -> Result<(), Error> {
            if self.peer_handle.is_none() {
                return Err(auth_error());
            }
            let (_, current) = Self::process(pid)?;
            let result = if current == *evidence {
                Ok(())
            } else {
                Err(auth_error())
            };
            self.peer_handle = None;
            result
        }
    }

    pub fn run(args: HelperArgs) -> Result<(), Error> {
        let mut io = SystemPipe::connect(&args, DEFAULT_AUTH_DEADLINE.as_millis() as u32)?;
        if io.server_pid()? != args.gui_pid {
            return Err(auth_error());
        }
        let mut verifier = SystemPeerVerifier::new();
        serve_authenticated_session(
            &mut io,
            &args,
            &mut verifier,
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
