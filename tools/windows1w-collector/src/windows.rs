//! Windows-only native calls for the read-only research collector.
//!
//! This module is deliberately not used by tests. The public library boundary
//! remains fakeable, while this implementation contains only the fixed native
//! calls required by the Windows1W evidence contract.

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID, SetLastError};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::SystemInformation::{
    FIRMWARE_TYPE, FirmwareTypeBios as FIRMWARE_TYPE_BIOS, FirmwareTypeUefi as FIRMWARE_TYPE_UEFI,
    FirmwareTypeUnknown as FIRMWARE_TYPE_UNKNOWN, GetFirmwareType,
};
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableExW;

use boothop_core::BootId;

use crate::{
    CallError, FirmwareType, MAX_PAYLOAD_BYTES, PrivilegeState, ReadOutcome, ReadStatus,
    VariableName, WindowsCalls,
};

const CURRENT_PROCESS_PSEUDO_HANDLE: HANDLE = -1isize as *mut c_void;
const FIRMWARE_GUID: &str = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
const SYSTEM_ENVIRONMENT_PRIVILEGE: &str = "SeSystemEnvironmentPrivilege";
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

#[derive(Default)]
pub struct WindowsBackend {
    token: HANDLE,
    previous_privilege: Option<TOKEN_PRIVILEGES>,
    enable_completed: bool,
}

impl WindowsBackend {
    pub const fn new() -> Self {
        Self {
            token: null_mut(),
            previous_privilege: None,
            enable_completed: false,
        }
    }

    fn close_token(&mut self) -> Result<(), CallError> {
        if self.token.is_null() {
            return Ok(());
        }
        let token = self.token;
        // Mark the handle consumed before calling into the OS so every owned
        // token has exactly one close attempt, even if closing reports error.
        self.token = null_mut();
        let closed = unsafe { CloseHandle(token) };
        if closed == 0 {
            return Err(CallError::new(unsafe { GetLastError() }));
        }
        Ok(())
    }

    fn close_after_error(&mut self, error: CallError) -> Result<PrivilegeState, CallError> {
        match self.close_token() {
            Ok(()) => Err(error),
            Err(close_error) => Err(close_error),
        }
    }

    fn rollback_and_close(
        &mut self,
        previous: Option<TOKEN_PRIVILEGES>,
        error: CallError,
    ) -> Result<PrivilegeState, CallError> {
        let rollback = if let Some(previous) = previous {
            unsafe { SetLastError(0) };
            let restored = unsafe {
                AdjustTokenPrivileges(
                    self.token,
                    0,
                    &previous,
                    std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    null_mut(),
                    null_mut(),
                )
            };
            let restore_error = unsafe { GetLastError() };
            if restored == 0 || restore_error == ERROR_NOT_ALL_ASSIGNED {
                Some(CallError::new(if restored == 0 {
                    restore_error
                } else {
                    ERROR_NOT_ALL_ASSIGNED
                }))
            } else {
                None
            }
        } else {
            None
        };
        let close = self.close_token();
        if let Some(rollback_error) = rollback {
            return Err(rollback_error);
        }
        close?;
        Err(error)
    }
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        if self.enable_completed {
            let _ = self.restore_privilege(PrivilegeState { was_enabled: false });
        } else {
            let _ = self.close_token();
        }
    }
}

impl WindowsCalls for WindowsBackend {
    fn firmware_type(&mut self) -> Result<FirmwareType, CallError> {
        let mut firmware_type: FIRMWARE_TYPE = FIRMWARE_TYPE_UNKNOWN;
        let ok = unsafe { GetFirmwareType(&mut firmware_type) };
        if ok == 0 {
            return Err(CallError::new(unsafe { GetLastError() }));
        }
        Ok(match firmware_type {
            FIRMWARE_TYPE_UEFI => FirmwareType::Uefi,
            FIRMWARE_TYPE_BIOS => FirmwareType::Bios,
            other => FirmwareType::Unknown(other as u32),
        })
    }

    fn enable_privilege(&mut self) -> Result<PrivilegeState, CallError> {
        if !self.token.is_null() || self.previous_privilege.is_some() {
            return Err(CallError::new(ERROR_INVALID_PARAMETER));
        }

        let mut token: HANDLE = null_mut();
        let opened = unsafe {
            OpenProcessToken(
                CURRENT_PROCESS_PSEUDO_HANDLE,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        };
        if opened == 0 {
            return Err(CallError::new(unsafe { GetLastError() }));
        }
        if token.is_null() {
            return self.close_after_error(CallError::new(ERROR_INVALID_HANDLE));
        }
        self.token = token;

        let privilege_name: Vec<u16> = SYSTEM_ENVIRONMENT_PRIVILEGE
            .encode_utf16()
            .chain([0])
            .collect();
        let mut luid = LUID::default();
        let looked_up =
            unsafe { LookupPrivilegeValueW(null(), privilege_name.as_ptr(), &mut luid) };
        if looked_up == 0 {
            return self.close_after_error(CallError::new(unsafe { GetLastError() }));
        }

        let requested = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut returned_length = 0u32;
        let adjusted = unsafe {
            SetLastError(0);
            AdjustTokenPrivileges(
                self.token,
                0,
                &requested,
                std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut previous,
                &mut returned_length,
            )
        };
        let adjust_error = unsafe { GetLastError() };
        if adjusted == 0 {
            return self.close_after_error(CallError::new(adjust_error));
        }
        if adjust_error == ERROR_NOT_ALL_ASSIGNED {
            let previous = (previous.PrivilegeCount > 0).then_some(previous);
            return self.rollback_and_close(previous, CallError::new(ERROR_NOT_ALL_ASSIGNED));
        }
        if previous.PrivilegeCount == 0 {
            self.enable_completed = true;
            return Ok(PrivilegeState { was_enabled: true });
        }
        if previous.PrivilegeCount != 1
            || previous.Privileges[0].Luid.LowPart != luid.LowPart
            || previous.Privileges[0].Luid.HighPart != luid.HighPart
            || (returned_length as usize) < std::mem::size_of::<TOKEN_PRIVILEGES>()
        {
            let rollback_previous = (previous.PrivilegeCount > 0).then_some(TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                ..previous
            });
            return self
                .rollback_and_close(rollback_previous, CallError::new(ERROR_INVALID_PARAMETER));
        }

        let state = PrivilegeState {
            was_enabled: previous.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED != 0,
        };
        self.previous_privilege = Some(previous);
        self.enable_completed = true;
        Ok(state)
    }

    fn restore_privilege(&mut self, _state: PrivilegeState) -> Result<(), CallError> {
        if !self.enable_completed {
            return Err(CallError::new(ERROR_INVALID_HANDLE));
        }
        self.enable_completed = false;
        let adjustment = if let Some(previous) = self.previous_privilege.take() {
            unsafe { SetLastError(0) };
            let restored = unsafe {
                AdjustTokenPrivileges(
                    self.token,
                    0,
                    &previous,
                    std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    null_mut(),
                    null_mut(),
                )
            };
            let restore_error = unsafe { GetLastError() };
            if restored == 0 || restore_error == ERROR_NOT_ALL_ASSIGNED {
                Err(CallError::new(if restored == 0 {
                    restore_error
                } else {
                    ERROR_NOT_ALL_ASSIGNED
                }))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        };
        let close = self.close_token();
        match adjustment {
            Err(error) => Err(error),
            Ok(()) => close,
        }
    }

    fn read_variable(&mut self, variable: VariableName, buffer_size: usize) -> ReadOutcome {
        if buffer_size == 0 || buffer_size > MAX_PAYLOAD_BYTES {
            return ReadOutcome::failure(0, ERROR_INVALID_PARAMETER);
        }

        let name: Vec<u16> = variable_name(variable).encode_utf16().chain([0]).collect();
        let guid: Vec<u16> = FIRMWARE_GUID.encode_utf16().chain([0]).collect();
        let mut buffer = vec![0u8; buffer_size];
        let mut attributes = 0u32;
        unsafe { SetLastError(0) };
        let returned = unsafe {
            GetFirmwareEnvironmentVariableExW(
                name.as_ptr(),
                guid.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer_size as u32,
                &mut attributes,
            )
        };
        let last_error = unsafe { GetLastError() };
        if returned != 0 {
            let count = returned as usize;
            if count > buffer_size {
                return ReadOutcome::failure(0, ERROR_INVALID_PARAMETER);
            }
            buffer.truncate(count);
            return ReadOutcome::success_with_last_error(attributes, buffer, last_error);
        }

        // Capture this immediately: no helper/native call is allowed between
        // the firmware API and the diagnostic error value.
        let error = last_error;
        if error == ERROR_INSUFFICIENT_BUFFER {
            let required_size = buffer_size
                .checked_mul(2)
                .unwrap_or(MAX_PAYLOAD_BYTES.saturating_add(1));
            return ReadOutcome::buffer_too_small(required_size, attributes);
        }
        ReadOutcome {
            status: ReadStatus::Error,
            bytes: Vec::new(),
            bytes_returned: 0,
            last_error: error,
            attributes,
            buffer_too_small: false,
            required_size: 0,
        }
    }
}

fn variable_name(variable: VariableName) -> String {
    match variable {
        VariableName::BootOrder => "BootOrder".to_owned(),
        VariableName::BootCurrent => "BootCurrent".to_owned(),
        VariableName::BootNext => "BootNext".to_owned(),
        VariableName::Boot(BootId(id)) => format!("Boot{id:04X}"),
    }
}
