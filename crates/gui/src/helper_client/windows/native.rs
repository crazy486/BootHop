//! Win32 implementation of the GUI transport. This module is never linked
//! on non-Windows hosts, and all policy inputs are fixed by the parent module.

use super::{HELPER_IMAGE_PATH, WindowsLaunchSpec, WindowsPipeSpec};
use crate::helper_client::{Event, TransportError};
use boothop_protocol::RequestId;
use std::{
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    },
    Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
        TokenElevation, TokenIntegrityLevel, TokenUser,
    },
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile},
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, OpenProcessToken, QueryFullProcessImageNameW,
            WaitForSingleObject,
        },
    },
    UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
};

const ERROR_CANCELLED: u32 = 1223;
const WAIT_TIMEOUT: u32 = 258;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub struct SystemWindowsBoundary {
    epoch: Instant,
    pipe: Option<Handle>,
    helper: Option<Handle>,
    helper_pid: u32,
    session_id: u32,
    connected: bool,
}

impl Default for SystemWindowsBoundary {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            pipe: None,
            helper: None,
            helper_pid: 0,
            session_id: 0,
            connected: false,
        }
    }
}

impl SystemWindowsBoundary {
    pub fn system() -> Self {
        Self::default()
    }

    fn sid() -> Result<String, TransportError> {
        let process = unsafe { GetCurrentProcess() };
        let mut token = null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
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
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                raw.as_mut_ptr().cast(),
                (raw.len() * 8) as u32,
                &mut size,
            )
        } == 0
            || (size as usize) < std::mem::size_of::<TOKEN_USER>()
        {
            return Err(TransportError::Io);
        }
        let user = unsafe { &*raw.as_ptr().cast::<TOKEN_USER>() };
        if user.User.Sid.is_null() {
            return Err(TransportError::Io);
        }
        let mut text = null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 || text.is_null() {
            return Err(TransportError::Io);
        }
        let mut len = 0;
        unsafe {
            while len < 184 && *text.add(len) != 0 {
                len += 1;
            }
        }
        let value = unsafe { String::from_utf16(std::slice::from_raw_parts(text, len)) }
            .map_err(|_| TransportError::Io)?;
        unsafe {
            LocalFree(text.cast());
        }
        Ok(value)
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
            return Err(TransportError::Authentication);
        }
        let token = Handle(token);
        let mut elevated = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0;
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                (&mut elevated as *mut TOKEN_ELEVATION).cast::<core::ffi::c_void>(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } == 0
            || elevated.TokenIsElevated == 0
        {
            return Err(TransportError::Authentication);
        }
        let mut integrity = vec![0u64; 128];
        let mut integrity_len = 0;
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                integrity.as_mut_ptr().cast(),
                (integrity.len() * 8) as u32,
                &mut integrity_len,
            )
        } == 0
            || (integrity_len as usize) < std::mem::size_of::<TOKEN_MANDATORY_LABEL>()
        {
            return Err(TransportError::Authentication);
        }
        let label = unsafe { &*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
        let count = unsafe { GetSidSubAuthorityCount(label.Label.Sid) };
        if count.is_null()
            || unsafe {
                *count == 0 || *GetSidSubAuthority(label.Label.Sid, u32::from(*count) - 1) < 0x3000
            }
        {
            return Err(TransportError::Authentication);
        }
        let mut image = vec![0u16; 32768];
        let mut length = image.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle, 0, image.as_mut_ptr(), &mut length) } == 0 {
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
        if unsafe { WaitForSingleObject(helper, 0) } != WAIT_TIMEOUT || self.helper_pid == 0 {
            return Ok(Event::Exit(-1));
        }
        Self::authenticate_helper(helper, self.helper_pid, self.session_id)?;
        let mut bytes = vec![0u8; 4096];
        let mut read = 0;
        let ok = unsafe {
            ReadFile(
                pipe,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(TransportError::Io);
        }
        bytes.truncate(read as usize);
        Ok(Event::Stdout(bytes))
    }
    fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), TransportError> {
        let pipe = self.pipe.as_ref().ok_or(TransportError::Io)?.0;
        if self.epoch.elapsed() >= deadline {
            return Err(TransportError::Timeout);
        }
        let mut written = 0;
        if unsafe {
            WriteFile(
                pipe,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                null_mut(),
            )
        } == 0
            || written != bytes.len() as u32
        {
            return Err(TransportError::Io);
        }
        Ok(())
    }
    fn stop(&mut self) {
        self.connected = false;
        self.pipe.take();
        self.helper.take();
        self.helper_pid = 0;
        self.session_id = 0;
    }
    fn start(&mut self, request_id: &RequestId) -> Result<(), TransportError> {
        let gui_pid = unsafe { GetCurrentProcessId() };
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
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                &attributes,
            )
        };
        unsafe {
            LocalFree(descriptor.cast());
        }
        if pipe.is_null() || pipe == INVALID_HANDLE_VALUE {
            return Err(TransportError::Io);
        }
        self.pipe = Some(Handle(pipe));
        let launch = WindowsLaunchSpec::for_request(request_id.clone(), gui_pid);
        let helper = Self::launch(&launch)?;
        self.helper = Some(Handle(helper));
        if unsafe { ConnectNamedPipe(pipe, null_mut()) } == 0 && unsafe { GetLastError() } != 535 {
            return Err(TransportError::Authentication);
        }
        let mut peer_pid = 0;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut peer_pid) } == 0 {
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
            return Err(TransportError::Authentication);
        }
        Self::authenticate_helper(helper, peer_pid, gui_session)?;
        self.helper_pid = peer_pid;
        self.session_id = gui_session;
        self.connected = true;
        Ok(())
    }
}
