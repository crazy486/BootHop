//! Win32 implementation of the GUI transport. This module is never linked
//! on non-Windows hosts, and all policy inputs are fixed by the parent module.

use super::{FileIdentity, HELPER_IMAGE_PATH, WatchdogState, WindowsLaunchSpec, WindowsPipeSpec};
use crate::helper_client::{Event, NativeIoStage, TransportError};
use boothop_protocol::RequestId;
use std::{
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, GetLastError,
        HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0,
    },
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    },
    Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenIntegrityLevel,
        TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_OVERLAPPED, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle, GetFinalPathNameByHandleW, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED},
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
            OpenProcessToken, QueryFullProcessImageNameW, WaitForSingleObject,
        },
    },
    UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
};

const ERROR_CANCELLED: u32 = 1223;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_NO_DATA: u32 = 232;
const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
const STILL_ACTIVE: u32 = 259;
const WAIT_TIMEOUT: u32 = 258;

struct Handle(HANDLE);
// A boundary is moved into the controller's single worker and never shared;
// Windows kernel handles are process-wide synchronization objects whose
// ownership can safely transfer between threads.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null()
            && self.0 != INVALID_HANDLE_VALUE
            && unsafe { CloseHandle(self.0) } == 0
        {
            let _error = unsafe { GetLastError() };
            // A native handle must never disappear silently on a
            // security-critical failure path.
            std::process::abort();
        }
    }
}
impl Handle {
    fn close_checked(self) -> Result<(), TransportError> {
        let handle = self.0;
        if unsafe { CloseHandle(handle) } == 0 {
            let _error = unsafe { GetLastError() };
            // Keep ownership until Drop retries the close; if that retry also
            // fails Drop aborts before a security-critical handle is lost.
            drop(self);
            Err(TransportError::Io)
        } else {
            std::mem::forget(self);
            Ok(())
        }
    }
}

fn free_local(ptr: *mut core::ffi::c_void) -> Result<(), TransportError> {
    if ptr.is_null() {
        return Ok(());
    }
    if unsafe { LocalFree(ptr.cast()) }.is_null() {
        Ok(())
    } else {
        Err(TransportError::Io)
    }
}

fn native_io(stage: NativeIoStage) -> TransportError {
    TransportError::NativeIo {
        stage,
        raw_code: unsafe { GetLastError() },
    }
}

struct WatchdogShared {
    state: WatchdogState,
    worker_started: bool,
    worker_finished: bool,
    abort_issued: bool,
}

struct Watchdog {
    shared: std::sync::Arc<(std::sync::Mutex<WatchdogShared>, std::sync::Condvar)>,
    deadline: Instant,
    abort: std::sync::Arc<dyn Fn() + Send + Sync + 'static>,
    worker: Option<std::thread::JoinHandle<()>>,
}

enum IoCompletion {
    Completed(u32),
    Aborted,
    PipeClosed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IoKind {
    Connect,
    Read,
    Write,
}

fn is_pipe_closed(error: u32) -> bool {
    matches!(
        error,
        ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
    )
}
impl Watchdog {
    fn arm(deadline: Instant) -> Self {
        Self::arm_with_abort(deadline, std::sync::Arc::new(|| std::process::abort()))
    }
    fn arm_with_abort(
        deadline: Instant,
        abort: std::sync::Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Self {
        let shared = std::sync::Arc::new((
            std::sync::Mutex::new(WatchdogShared {
                state: WatchdogState::Armed,
                worker_started: false,
                worker_finished: false,
                abort_issued: false,
            }),
            std::sync::Condvar::new(),
        ));
        let thread_shared = shared.clone();
        let thread_abort = abort.clone();
        let worker = std::thread::Builder::new()
            .name("boothop-windows-client-deadline".into())
            .spawn(move || {
                let (lock, wake) = &*thread_shared;
                let mut guard = match lock.lock() {
                    Ok(guard) => guard,
                    Err(_) => std::process::abort(),
                };
                guard.worker_started = true;
                wake.notify_all();
                loop {
                    if guard.state != WatchdogState::Armed {
                        guard.worker_finished = true;
                        wake.notify_all();
                        return;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        guard.state = WatchdogState::Expired;
                        guard.abort_issued = true;
                        wake.notify_all();
                        drop(guard);
                        thread_abort();
                        guard = match lock.lock() {
                            Ok(guard) => guard,
                            Err(_) => std::process::abort(),
                        };
                        guard.worker_finished = true;
                        wake.notify_all();
                        return;
                    }
                    let remaining = deadline.duration_since(now);
                    guard = match wake.wait_timeout(guard, remaining) {
                        Ok((guard, _)) => guard,
                        Err(_) => std::process::abort(),
                    };
                }
            })
            .unwrap_or_else(|_| std::process::abort());

        // Do not return until the worker has observed Armed. This closes the
        // construction race with synchronous ShellExecuteExW/connect work.
        let (lock, wake) = &*shared;
        let mut guard = match lock.lock() {
            Ok(guard) => guard,
            Err(_) => std::process::abort(),
        };
        while !guard.worker_started {
            guard = match wake.wait(guard) {
                Ok(guard) => guard,
                Err(_) => std::process::abort(),
            };
        }
        drop(guard);
        Self {
            shared,
            deadline,
            abort,
            worker: Some(worker),
        }
    }
    fn disarm(&mut self) {
        let should_abort = {
            let (lock, wake) = &*self.shared;
            let mut guard = match lock.lock() {
                Ok(guard) => guard,
                Err(_) => std::process::abort(),
            };
            let next = if guard.state == WatchdogState::Armed && Instant::now() < self.deadline {
                WatchdogState::Disarmed
            } else if guard.state == WatchdogState::Armed || guard.state == WatchdogState::Expired {
                WatchdogState::Expired
            } else {
                WatchdogState::Disarmed
            };
            guard.state = next;
            let should_abort = next == WatchdogState::Expired && !guard.abort_issued;
            if should_abort {
                guard.abort_issued = true;
            }
            wake.notify_all();
            should_abort
        };
        if self.worker.is_some() {
            let (lock, wake) = &*self.shared;
            let guard = match lock.lock() {
                Ok(guard) => guard,
                Err(_) => std::process::abort(),
            };
            let (guard, timeout) =
                match wake.wait_timeout_while(guard, Duration::from_millis(100), |state| {
                    !state.worker_finished
                }) {
                    Ok(value) => value,
                    Err(_) => std::process::abort(),
                };
            if timeout.timed_out() && !guard.worker_finished {
                std::process::abort();
            }
        }
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            std::process::abort();
        }
        if should_abort {
            (self.abort)();
        }
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        self.disarm();
    }
}

pub struct SystemWindowsBoundary {
    epoch: Instant,
    pipe: Option<Handle>,
    helper: Option<Handle>,
    helper_file: Option<Handle>,
    helper_file_identity: Option<FileIdentity>,
    operation_watchdog: Option<Watchdog>,
    helper_pid: u32,
    session_id: u32,
    connected: bool,
    request_committed: bool,
    cleanup_error: Option<TransportError>,
}

impl Default for SystemWindowsBoundary {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            pipe: None,
            helper: None,
            helper_file: None,
            helper_file_identity: None,
            operation_watchdog: None,
            helper_pid: 0,
            session_id: 0,
            connected: false,
            request_committed: false,
            cleanup_error: None,
        }
    }
}

/// Validate a SID's complete declared byte region before passing it to any
/// Win32 SID helper. TOKEN_USER/TOKEN_MANDATORY_LABEL contain an embedded
/// pointer, so the pointer must be proven to refer to the same returned buffer
/// rather than merely being non-null.
fn sid_region(
    base: *const u8,
    declared: usize,
    sid: *mut core::ffi::c_void,
    minimum_offset: usize,
) -> Result<(usize, usize), TransportError> {
    if sid.is_null() {
        return Err(TransportError::Authentication);
    }
    let offset = (sid as usize)
        .checked_sub(base as usize)
        .ok_or(TransportError::Authentication)?;
    if offset < minimum_offset
        || !offset.is_multiple_of(std::mem::align_of::<u32>())
        || offset.checked_add(8).is_none()
        || offset + 8 > declared
    {
        return Err(TransportError::Authentication);
    }
    let header = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
    if header[0] != 1 || header[1] == 0 {
        return Err(TransportError::Authentication);
    }
    let length = 8usize
        .checked_add(
            usize::from(header[1])
                .checked_mul(4)
                .ok_or(TransportError::Authentication)?,
        )
        .ok_or(TransportError::Authentication)?;
    if offset.checked_add(length).is_none() || offset + length > declared {
        return Err(TransportError::Authentication);
    }
    Ok((usize::from(header[1]), length))
}

impl SystemWindowsBoundary {
    pub fn system() -> Self {
        Self::default()
    }

    fn open_fixed_helper() -> Result<(Handle, FileIdentity), TransportError> {
        let path: Vec<u16> = HELPER_IMAGE_PATH.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe {
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
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(native_io(NativeIoStage::HelperFileOpen));
        }
        let handle = Handle(handle);
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let got_info = unsafe { GetFileInformationByHandle(handle.0, &mut info) } != 0;
        if !got_info {
            return Err(native_io(NativeIoStage::HelperIdentityRead));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(TransportError::Authentication);
        }
        let mut canonical = vec![0u16; 32768];
        let count = unsafe {
            GetFinalPathNameByHandleW(
                handle.0,
                canonical.as_mut_ptr(),
                canonical.len() as u32,
                FILE_NAME_NORMALIZED,
            )
        };
        if count == 0 || count as usize >= canonical.len() {
            return Err(native_io(NativeIoStage::HelperPathResolve));
        }
        canonical.truncate(count as usize);
        let canonical =
            String::from_utf16(&canonical).map_err(|_| TransportError::Authentication)?;
        let canonical = canonical.strip_prefix(r"\\?\").unwrap_or(&canonical);
        if canonical != HELPER_IMAGE_PATH {
            return Err(TransportError::Authentication);
        }
        let identity = FileIdentity {
            volume_serial: u64::from(info.dwVolumeSerialNumber),
            file_id: (u128::from(info.nFileIndexHigh) << 32) | u128::from(info.nFileIndexLow),
            regular_file: true,
            reparse: false,
        };
        if identity.volume_serial == 0 || identity.file_id == 0 {
            return Err(TransportError::Authentication);
        }
        Ok((handle, identity))
    }

    fn revalidate_fixed_helper(&self) -> Result<(), TransportError> {
        let Some(expected) = self.helper_file_identity.as_ref() else {
            return Err(TransportError::Authentication);
        };
        let (handle, current) = Self::open_fixed_helper()?;
        let equal = &current == expected;
        handle.close_checked()?;
        equal.then_some(()).ok_or(TransportError::Authentication)
    }

    fn io_deadline(&self, deadline: Duration) -> Instant {
        self.epoch + deadline
    }

    fn wait_io(
        &self,
        handle: HANDLE,
        overlapped: &mut OVERLAPPED,
        deadline: Duration,
        kind: IoKind,
    ) -> Result<IoCompletion, TransportError> {
        let end = self.io_deadline(deadline);
        let remaining = match end.checked_duration_since(Instant::now()) {
            Some(remaining) => remaining,
            None => {
                return match Self::cancel_and_join(handle, overlapped, kind)? {
                    IoCompletion::Aborted => Err(TransportError::Timeout),
                    completion => Ok(completion),
                };
            }
        };
        let timeout = remaining.as_millis().min(u128::from(u32::MAX)) as u32;
        let mut transferred = 0;
        if unsafe { GetOverlappedResultEx(handle, overlapped, &mut transferred, timeout, 1) } != 0 {
            return Ok(IoCompletion::Completed(transferred));
        }
        let error = unsafe { GetLastError() };
        // Cancellation is followed by a completion barrier before the event,
        // OVERLAPPED, and its backing buffer can be released.
        if error == 1460 || error == 258 {
            return match Self::cancel_and_join(handle, overlapped, kind)? {
                IoCompletion::Aborted => Err(TransportError::Timeout),
                completion => Ok(completion),
            };
        }
        // WAIT_FAILED and every unexpected result are still subject to an
        // outstanding operation race. Prove completion before returning an
        // ordinary error; an unprovable state aborts fail-closed.
        match Self::cancel_and_join(handle, overlapped, kind)? {
            IoCompletion::Aborted => Err(TransportError::Io),
            completion => Ok(completion),
        }
    }

    /// Cancel an issued overlapped operation and prove that the kernel has
    /// stopped using its event, OVERLAPPED, and caller-owned buffer. Any state
    /// that cannot be proven terminal aborts before those values can drop.
    fn cancel_and_join(
        handle: HANDLE,
        overlapped: &OVERLAPPED,
        kind: IoKind,
    ) -> Result<IoCompletion, TransportError> {
        let event = overlapped.hEvent;
        let cancel_ok = unsafe { CancelIoEx(handle, overlapped) } != 0;
        let cancel_error = if cancel_ok {
            0
        } else {
            unsafe { GetLastError() }
        };
        if !cancel_ok && cancel_error != ERROR_NOT_FOUND {
            std::process::abort();
        }
        if !cancel_ok {
            // ERROR_NOT_FOUND is only safe when the operation has already
            // signalled its event and GetOverlappedResult proves completion.
            if unsafe { WaitForSingleObject(event, 0) } != WAIT_OBJECT_0 {
                std::process::abort();
            }
        } else if unsafe { WaitForSingleObject(event, 1_000) } != WAIT_OBJECT_0 {
            std::process::abort();
        }
        let mut transferred = 0;
        let completed = unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 0) };
        let completion_error = if completed == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if completed == 0
            && completion_error != ERROR_OPERATION_ABORTED
            && !(kind == IoKind::Read && is_pipe_closed(completion_error))
        {
            std::process::abort();
        }
        if completed != 0 {
            Ok(IoCompletion::Completed(transferred))
        } else if kind == IoKind::Read && is_pipe_closed(completion_error) {
            Ok(IoCompletion::PipeClosed)
        } else {
            Ok(IoCompletion::Aborted)
        }
    }

    fn helper_exit_event(
        &self,
        helper: HANDLE,
        deadline: Duration,
    ) -> Result<Event, TransportError> {
        let remaining = self
            .io_deadline(deadline)
            .checked_duration_since(Instant::now())
            .ok_or(TransportError::Timeout)?;
        let wait_ms = remaining.as_millis().min(u128::from(u32::MAX)) as u32;
        let wait = unsafe { WaitForSingleObject(helper, wait_ms) };
        if wait == WAIT_FAILED {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        if wait == WAIT_TIMEOUT {
            return Err(TransportError::Timeout);
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(helper, &mut code) } == 0 {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        if code == STILL_ACTIVE {
            return Err(TransportError::Authentication);
        }
        Ok(Event::Exit(code as i32))
    }

    fn sid() -> Result<String, TransportError> {
        let process = unsafe { GetCurrentProcess() };
        let mut token = null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(native_io(NativeIoStage::ProcessTokenOpen));
        }
        let token = Handle(token);
        let mut size = 0;
        unsafe {
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size);
        }
        if size == 0 {
            return Err(native_io(NativeIoStage::TokenUserSize));
        }
        let mut raw = vec![0u64; (size as usize).div_ceil(std::mem::size_of::<u64>())];
        let token_info_ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                raw.as_mut_ptr().cast(),
                (raw.len() * 8) as u32,
                &mut size,
            )
        } != 0;
        if !token_info_ok {
            return Err(native_io(NativeIoStage::TokenUserRead));
        }
        if (size as usize) < std::mem::size_of::<TOKEN_USER>()
            || (size as usize) > raw.len() * std::mem::size_of::<u64>()
        {
            return Err(TransportError::NativeIo {
                stage: NativeIoStage::TokenUserValidate,
                raw_code: 0,
            });
        }
        let user = unsafe { &*raw.as_ptr().cast::<TOKEN_USER>() };
        let available = size as usize;
        sid_region(
            raw.as_ptr().cast(),
            available,
            user.User.Sid,
            std::mem::size_of::<TOKEN_USER>(),
        )
        .map_err(|_| TransportError::Io)?;
        let mut text = null_mut();
        let converted = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } != 0;
        if !converted {
            return Err(native_io(NativeIoStage::UserSidFormat));
        }
        if text.is_null() {
            return Err(TransportError::NativeIo {
                stage: NativeIoStage::UserSidValidate,
                raw_code: 0,
            });
        }
        let mut len = 0;
        unsafe {
            while len < 184 && *text.add(len) != 0 {
                len += 1;
            }
        }
        if len == 184 {
            free_local(text.cast()).map_err(|_| TransportError::NativeIo {
                stage: NativeIoStage::UserSidRelease,
                raw_code: 0,
            })?;
            return Err(TransportError::NativeIo {
                stage: NativeIoStage::UserSidValidate,
                raw_code: 0,
            });
        }
        let value = unsafe { String::from_utf16(std::slice::from_raw_parts(text, len)) };
        free_local(text.cast()).map_err(|_| TransportError::NativeIo {
            stage: NativeIoStage::UserSidRelease,
            raw_code: 0,
        })?;
        value.map_err(|_| TransportError::Io)
    }

    fn launch(spec: &WindowsLaunchSpec) -> Result<HANDLE, TransportError> {
        let file: Vec<u16> = spec.program.encode_utf16().chain(Some(0)).collect();
        let verb: Vec<u16> = spec.verb.encode_utf16().chain(Some(0)).collect();
        let params_text = spec.args.join(" ");
        let params: Vec<u16> = params_text.encode_utf16().chain(Some(0)).collect();
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: params.as_ptr(),
            ..Default::default()
        };
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            let error = unsafe { GetLastError() };
            return if error == ERROR_CANCELLED {
                Err(TransportError::Cancelled)
            } else {
                Err(TransportError::NativeIo {
                    stage: NativeIoStage::HelperLaunch,
                    raw_code: error,
                })
            };
        }
        if info.hProcess.is_null() {
            return Err(TransportError::Launch);
        }
        // This check makes the fixed identity visible at the native boundary;
        // the actual opened-handle comparison is performed below.
        if spec.program != HELPER_IMAGE_PATH {
            return Err(TransportError::Authentication);
        }
        Ok(info.hProcess)
    }

    fn authenticate_helper(
        handle: HANDLE,
        expected_pid: u32,
        expected_session: u32,
    ) -> Result<(), TransportError> {
        let pid = unsafe { windows_sys::Win32::System::Threading::GetProcessId(handle) };
        if pid != expected_pid {
            return Err(TransportError::Authentication);
        }
        let mut token = null_mut();
        if unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) } == 0 {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
        }
        let token = Handle(token);
        let mut elevated = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0;
        let elevation_ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                (&mut elevated as *mut TOKEN_ELEVATION).cast::<core::ffi::c_void>(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } != 0;
        if !elevation_ok {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
        }
        if returned as usize != std::mem::size_of::<TOKEN_ELEVATION>()
            || elevated.TokenIsElevated == 0
        {
            return Err(TransportError::Authentication);
        }
        let mut integrity = vec![0u64; 128];
        let mut integrity_len = 0;
        let integrity_ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                integrity.as_mut_ptr().cast(),
                (integrity.len() * 8) as u32,
                &mut integrity_len,
            )
        } != 0;
        if !integrity_ok {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
        }
        if (integrity_len as usize) < std::mem::size_of::<TOKEN_MANDATORY_LABEL>()
            || (integrity_len as usize) > integrity.len() * std::mem::size_of::<u64>()
        {
            return Err(TransportError::Authentication);
        }
        let label = unsafe { &*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
        let (count, sid_length) = sid_region(
            integrity.as_ptr().cast(),
            integrity_len as usize,
            label.Label.Sid,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>(),
        )?;
        let last_offset = sid_length
            .checked_sub(4)
            .ok_or(TransportError::Authentication)?;
        let sid_bytes =
            unsafe { std::slice::from_raw_parts(label.Label.Sid.cast::<u8>(), sid_length) };
        let last = u32::from_le_bytes(
            sid_bytes[last_offset..last_offset + 4]
                .try_into()
                .map_err(|_| TransportError::Authentication)?,
        );
        if count == 0 || last < 0x3000 {
            return Err(TransportError::Authentication);
        }
        let mut image = vec![0u16; 32768];
        let mut length = image.len() as u32;
        let image_ok =
            unsafe { QueryFullProcessImageNameW(handle, 0, image.as_mut_ptr(), &mut length) } != 0;
        if !image_ok {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
        }
        if length as usize > image.len() {
            return Err(TransportError::Authentication);
        }
        image.truncate(length as usize);
        if String::from_utf16(&image).ok().as_deref() != Some(HELPER_IMAGE_PATH) {
            return Err(TransportError::Authentication);
        }
        let mut session = 0;
        if unsafe {
            windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut session)
        } == 0
            || session == 0
            || session != expected_session
        {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
        }
        Ok(())
    }
}

impl super::WindowsBoundary for SystemWindowsBoundary {
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
    fn next(&mut self, deadline: Duration) -> Result<Event, TransportError> {
        if let Some(error) = self.cleanup_error.take() {
            return Err(error);
        }
        let pipe = self.pipe.as_ref().ok_or(TransportError::Io)?.0;
        if self.epoch.elapsed() >= deadline {
            return Err(TransportError::Timeout);
        }
        let helper = self
            .helper
            .as_ref()
            .ok_or(TransportError::Authentication)?
            .0;
        if self.helper_pid == 0 {
            return Err(TransportError::Authentication);
        }
        if unsafe { WaitForSingleObject(helper, 0) } == WAIT_FAILED {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        Self::authenticate_helper(helper, self.helper_pid, self.session_id)?;
        self.revalidate_fixed_helper()?;
        let mut bytes = vec![0u8; 4096];
        let mut read = 0;
        let event = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        let event = Handle(event);
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        if self.epoch.elapsed() >= deadline {
            event.close_checked()?;
            return Err(TransportError::Timeout);
        }
        let ok = unsafe {
            ReadFile(
                pipe,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut read,
                &mut overlapped,
            )
        };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            if is_pipe_closed(error) {
                return self.helper_exit_event(helper, deadline);
            }
            if error != ERROR_IO_PENDING {
                return Err(TransportError::Io);
            }
            match self.wait_io(pipe, &mut overlapped, deadline, IoKind::Read)? {
                IoCompletion::Completed(bytes) => read = bytes,
                IoCompletion::PipeClosed => return self.helper_exit_event(helper, deadline),
                IoCompletion::Aborted => unreachable!(),
            }
        }
        bytes.truncate(read as usize);
        event.close_checked()?;
        Ok(Event::Stdout(bytes))
    }
    fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), TransportError> {
        let pipe = self.pipe.as_ref().ok_or(TransportError::Io)?.0;
        if self.epoch.elapsed() >= deadline {
            return Err(TransportError::Timeout);
        }
        let helper = self
            .helper
            .as_ref()
            .ok_or(TransportError::Authentication)?
            .0;
        let liveness = unsafe { WaitForSingleObject(helper, 0) };
        if liveness == WAIT_FAILED {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        if liveness != WAIT_TIMEOUT {
            return Err(TransportError::Authentication);
        }
        Self::authenticate_helper(helper, self.helper_pid, self.session_id)?;
        self.revalidate_fixed_helper()?;
        let mut written = 0;
        let event = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        let event = Handle(event);
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        if self.epoch.elapsed() >= deadline {
            event.close_checked()?;
            return Err(TransportError::Timeout);
        }
        if unsafe {
            WriteFile(
                pipe,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                &mut overlapped,
            )
        } == 0
        {
            let error = unsafe { GetLastError() };
            if error != ERROR_IO_PENDING {
                return Err(TransportError::Io);
            }
            written = match self.wait_io(pipe, &mut overlapped, deadline, IoKind::Write)? {
                IoCompletion::Completed(bytes) => bytes,
                IoCompletion::Aborted | IoCompletion::PipeClosed => return Err(TransportError::Io),
            };
        }
        if written != bytes.len() as u32 {
            return Err(TransportError::Io);
        }
        self.request_committed = true;
        if let Err(error) = event.close_checked() {
            self.cleanup_error.get_or_insert(error);
        }
        Ok(())
    }
    fn stop(&mut self) {
        self.connected = false;
        let mut cleanup_error = None;
        for handle in [
            self.pipe.take(),
            self.helper.take(),
            self.helper_file.take(),
        ]
        .into_iter()
        .flatten()
        {
            if let Err(error) = handle.close_checked() {
                cleanup_error.get_or_insert(error);
            }
        }
        self.helper_pid = 0;
        self.session_id = 0;
        self.helper_file_identity = None;
        self.cleanup_error = cleanup_error.or(self.cleanup_error.take());
        // The operation watchdog is disarmed only after all security-critical
        // process/file/pipe handles have had their explicit close attempt.
        if let Some(mut watchdog) = self.operation_watchdog.take() {
            watchdog.disarm();
        }
    }
    fn take_cleanup_error(&mut self) -> Option<TransportError> {
        self.cleanup_error.take()
    }
    fn request_committed(&self) -> bool {
        self.request_committed
    }
    fn start_until(
        &mut self,
        request_id: &RequestId,
        deadline: Duration,
    ) -> Result<(), TransportError> {
        let mut watchdog = Watchdog::arm(self.epoch + deadline);
        let result = self.start_inner(request_id, deadline);
        watchdog.disarm();
        result
    }
    fn start(&mut self, request_id: &RequestId) -> Result<(), TransportError> {
        self.start_until(request_id, self.epoch.elapsed() + Duration::from_secs(120))
    }
}

impl SystemWindowsBoundary {
    fn start_inner(
        &mut self,
        request_id: &RequestId,
        deadline: Duration,
    ) -> Result<(), TransportError> {
        self.request_committed = false;
        self.cleanup_error = None;
        let gui_pid = unsafe { GetCurrentProcessId() };
        let (helper_file, helper_identity) = Self::open_fixed_helper()?;
        self.helper_file = Some(helper_file);
        self.helper_file_identity = Some(helper_identity.clone());
        let sid = Self::sid()?;
        let spec = WindowsPipeSpec::for_request(request_id.clone(), &sid);
        if !spec.is_secure() {
            return Err(TransportError::Authentication);
        }
        let name: Vec<u16> = spec.name().encode_utf16().chain(Some(0)).collect();
        let dacl: Vec<u16> = spec.dacl().encode_utf16().chain(Some(0)).collect();
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
            let error = unsafe { GetLastError() };
            let _ = free_local(descriptor.cast());
            return Err(TransportError::NativeIo {
                stage: NativeIoStage::PipeSecurityBuild,
                raw_code: error,
            });
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                &attributes,
            )
        };
        let pipe_error = if pipe.is_null() || pipe == INVALID_HANDLE_VALUE {
            unsafe { GetLastError() }
        } else {
            0
        };
        let descriptor_result =
            free_local(descriptor.cast()).map_err(|_| TransportError::NativeIo {
                stage: NativeIoStage::PipeSecurityRelease,
                raw_code: 0,
            });
        if pipe.is_null() || pipe == INVALID_HANDLE_VALUE {
            return Err(descriptor_result.err().unwrap_or(TransportError::NativeIo {
                stage: NativeIoStage::PipeCreate,
                raw_code: pipe_error,
            }));
        }
        let pipe = Handle(pipe);
        if let Err(error) = descriptor_result {
            pipe.close_checked()?;
            let _ = pipe_error;
            return Err(error);
        }
        let pipe_handle = pipe.0;
        self.pipe = Some(pipe);
        let launch = WindowsLaunchSpec::for_request(request_id.clone(), gui_pid);
        let helper = Self::launch(&launch)?;
        self.helper = Some(Handle(helper));
        let (reopened_file, reopened_identity) = Self::open_fixed_helper()?;
        reopened_file.close_checked()?;
        if reopened_identity != helper_identity {
            return Err(TransportError::Authentication);
        }
        let event = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        let event = Handle(event);
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        if self.epoch.elapsed() >= deadline {
            event.close_checked()?;
            return Err(TransportError::Timeout);
        }
        if unsafe { ConnectNamedPipe(pipe_handle, &mut overlapped) } == 0 {
            let error = unsafe { GetLastError() };
            if error == 535 {
                // The client won the connect race and the instance is ready.
            } else if error == ERROR_IO_PENDING {
                match self.wait_io(pipe_handle, &mut overlapped, deadline, IoKind::Connect)? {
                    IoCompletion::Completed(_) => {}
                    IoCompletion::Aborted | IoCompletion::PipeClosed => {
                        return Err(TransportError::Authentication);
                    }
                }
            } else {
                return Err(TransportError::Authentication);
            }
        }
        event.close_checked()?;
        if self.epoch.elapsed() >= deadline {
            return Err(TransportError::Timeout);
        }
        let mut peer_pid = 0;
        if unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut peer_pid) } == 0 {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
        }
        let mut gui_session = 0;
        if unsafe {
            windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                gui_pid,
                &mut gui_session,
            )
        } == 0
            || gui_session == 0
        {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
        }
        Self::authenticate_helper(helper, peer_pid, gui_session)?;
        self.helper_pid = peer_pid;
        self.session_id = gui_session;
        self.operation_watchdog = Some(Watchdog::arm(Instant::now() + Duration::from_secs(30)));
        self.connected = true;
        Ok(())
    }
}
