//! Win32 implementation of the GUI transport. This module is never linked
//! on non-Windows hosts, and all policy inputs are fixed by the parent module.

use super::{FileIdentity, HELPER_IMAGE_PATH, WindowsLaunchSpec, WindowsPipeSpec};
use crate::helper_client::{Event, TransportError};
use boothop_protocol::RequestId;
use std::{
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, GetLastError,
        HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED,
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
        IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED},
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
const STILL_ACTIVE: u32 = 259;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null()
            && self.0 != INVALID_HANDLE_VALUE
            && unsafe { CloseHandle(self.0) } == 0
        {
            // A native handle must never disappear silently on a
            // security-critical failure path.
            std::process::abort();
        }
    }
}
impl Handle {
    fn close_checked(self) -> Result<(), TransportError> {
        let handle = self.0;
        std::mem::forget(self);
        if unsafe { CloseHandle(handle) } == 0 {
            let _error = unsafe { GetLastError() };
            Err(TransportError::Io)
        } else {
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

struct Watchdog {
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Watchdog {
    fn arm(deadline: Instant) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let armed = std::sync::Arc::new(AtomicBool::new(true));
        let worker = armed.clone();
        std::thread::Builder::new()
            .name("boothop-windows-client-deadline".into())
            .spawn(move || {
                let now = Instant::now();
                if deadline > now {
                    std::thread::sleep(deadline.duration_since(now));
                }
                if worker.swap(false, Ordering::AcqRel) {
                    // Ignored UAC or a stuck Win32 wait is fail-closed. The
                    // watchdog is intentionally not cancellable by cleanup.
                    std::process::abort();
                }
            })
            .expect("watchdog thread must start");
        Self { armed }
    }
    fn disarm(&self) {
        use std::sync::atomic::Ordering;
        self.armed.store(false, Ordering::Release);
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
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
        }
        let handle = Handle(handle);
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let got_info = unsafe { GetFileInformationByHandle(handle.0, &mut info) } != 0;
        if !got_info {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
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
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Authentication);
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
    ) -> Result<u32, TransportError> {
        let end = self.io_deadline(deadline);
        let remaining = end
            .checked_duration_since(Instant::now())
            .ok_or(TransportError::Timeout)?;
        let timeout = remaining.as_millis().min(u128::from(u32::MAX)) as u32;
        let mut transferred = 0;
        if unsafe { GetOverlappedResultEx(handle, overlapped, &mut transferred, timeout, 1) } != 0 {
            return Ok(transferred);
        }
        let error = unsafe { GetLastError() };
        // Cancellation is followed by a completion barrier before the event,
        // OVERLAPPED, and its backing buffer can be released.
        if error == 1460 || error == 258 {
            let cancel = unsafe { CancelIoEx(handle, overlapped) };
            let cancel_error = if cancel == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            let mut completed = 0;
            let barrier =
                unsafe { GetOverlappedResultEx(handle, overlapped, &mut completed, 1_000, 1) };
            let barrier_error = if barrier == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if barrier_error != 0 && barrier_error != ERROR_OPERATION_ABORTED {
                return Err(TransportError::Io);
            }
            if cancel_error != 0 && cancel_error != ERROR_NOT_FOUND {
                return Err(TransportError::Io);
            }
            return Err(TransportError::Timeout);
        }
        let _ = ERROR_IO_PENDING;
        Err(TransportError::Io)
    }

    fn sid() -> Result<String, TransportError> {
        let process = unsafe { GetCurrentProcess() };
        let mut token = null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        let token = Handle(token);
        let mut size = 0;
        unsafe {
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size);
        }
        if size == 0 {
            return Err(TransportError::Io);
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
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        if (size as usize) < std::mem::size_of::<TOKEN_USER>()
            || (size as usize) > raw.len() * std::mem::size_of::<u64>()
        {
            return Err(TransportError::Io);
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
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        if text.is_null() {
            return Err(TransportError::Io);
        }
        let mut len = 0;
        unsafe {
            while len < 184 && *text.add(len) != 0 {
                len += 1;
            }
        }
        if len == 184 {
            free_local(text.cast())?;
            return Err(TransportError::Io);
        }
        let value = unsafe { String::from_utf16(std::slice::from_raw_parts(text, len)) };
        free_local(text.cast())?;
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
            return if unsafe { GetLastError() } == ERROR_CANCELLED {
                Err(TransportError::Cancelled)
            } else {
                Err(TransportError::Launch)
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
            if error == ERROR_BROKEN_PIPE {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(helper, &mut code) } == 0 {
                    let _error = unsafe { GetLastError() };
                    return Err(TransportError::Io);
                }
                if code == STILL_ACTIVE {
                    return Err(TransportError::Authentication);
                }
                return Ok(Event::Exit(code as i32));
            }
            if error != ERROR_IO_PENDING {
                return Err(TransportError::Io);
            }
            read = self.wait_io(pipe, &mut overlapped, deadline)?;
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
            written = self.wait_io(pipe, &mut overlapped, deadline)?;
        }
        if written != bytes.len() as u32 {
            return Err(TransportError::Io);
        }
        event.close_checked()?;
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
        self.cleanup_error = cleanup_error;
        // The operation watchdog is disarmed only after all security-critical
        // process/file/pipe handles have had their explicit close attempt.
        if let Some(watchdog) = self.operation_watchdog.take() {
            watchdog.disarm();
        }
    }
    fn take_cleanup_error(&mut self) -> Option<TransportError> {
        self.cleanup_error.take()
    }
    fn start_until(
        &mut self,
        request_id: &RequestId,
        deadline: Duration,
    ) -> Result<(), TransportError> {
        let watchdog = Watchdog::arm(self.epoch + deadline);
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
            let _error = unsafe { GetLastError() };
            let _ = free_local(descriptor.cast());
            return Err(TransportError::Io);
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
        free_local(descriptor.cast())?;
        if pipe.is_null() || pipe == INVALID_HANDLE_VALUE {
            let _error = unsafe { GetLastError() };
            return Err(TransportError::Io);
        }
        self.pipe = Some(Handle(pipe));
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
        if unsafe { ConnectNamedPipe(pipe, &mut overlapped) } == 0 {
            let error = unsafe { GetLastError() };
            if error == 535 {
                // The client won the connect race and the instance is ready.
            } else if error == ERROR_IO_PENDING {
                self.wait_io(pipe, &mut overlapped, deadline)?;
            } else {
                return Err(TransportError::Authentication);
            }
        }
        event.close_checked()?;
        let mut peer_pid = 0;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut peer_pid) } == 0 {
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
