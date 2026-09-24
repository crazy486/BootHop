use boothop_core::{BootId, EnumerationDiagnostic, Error, OptionInventory, parse_load_option};

#[cfg(windows)]
use super::privilege::native::NativeTokenCalls;
#[cfg(windows)]
use super::privilege::with_system_environment_privilege;

pub const INITIAL_BUFFER_BYTES: usize = 4 * 1024;
pub const MAX_VARIABLE_BYTES: usize = 1_048_576;
pub const MAX_RAW_INVENTORY_BYTES: usize = 1_048_576;
/// Compatibility names for callers that reason about payload and inventory
/// bounds separately; both are the same one-MiB hard policy limit.
pub const MAX_PAYLOAD_BYTES: usize = MAX_VARIABLE_BYTES;
pub const MAX_ENUMERATION_BYTES: usize = MAX_RAW_INVENTORY_BYTES;
pub const BOOT_ATTRIBUTES: u32 = 0x7;
pub const BOOT_CURRENT_ATTRIBUTES: u32 = 0x6;
/// The UEFI global-variable GUID used by every production firmware call.
pub const GLOBAL_VARIABLE_GUID: &str = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
#[cfg(any(windows, test))]
const ERROR_ENVVAR_NOT_FOUND: i32 = 203;

/// Validate a caller-provided native read size before it reaches the Win32
/// boundary. The policy limit also makes the usize-to-u32 conversion explicit.
pub fn validate_native_buffer_size(buffer_size: usize) -> Result<u32, CallError> {
    u32::try_from(buffer_size)
        .ok()
        .filter(|size| *size != 0 && buffer_size <= MAX_VARIABLE_BYTES)
        .ok_or_else(|| CallError::new(87))
}

/// The only variable names the firmware boundary can address.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VariableName {
    BootOrder,
    BootCurrent,
    BootNext,
    Boot(BootId),
}

impl std::fmt::Display for VariableName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BootOrder => f.write_str("BootOrder"),
            Self::BootCurrent => f.write_str("BootCurrent"),
            Self::BootNext => f.write_str("BootNext"),
            Self::Boot(id) => write!(f, "Boot{:04X}", id.0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareType {
    Uefi,
    Bios,
    Unknown(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallError {
    pub raw_code: i32,
}

impl CallError {
    pub const fn new(raw_code: i32) -> Self {
        Self { raw_code }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadStatus {
    Success,
    Missing,
    Error,
}

/// A faithful result from GetFirmwareEnvironmentVariableExW, including the
/// separately returned attribute value and immediate last-error snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOutcome {
    pub status: ReadStatus,
    pub bytes: Vec<u8>,
    pub bytes_returned: usize,
    pub last_error: i32,
    pub attributes: u32,
    pub buffer_too_small: bool,
    pub required_size: usize,
}

impl ReadOutcome {
    pub fn success(attributes: u32, bytes: Vec<u8>) -> Self {
        Self::success_with_last_error(attributes, bytes, 0)
    }

    pub fn success_with_last_error(attributes: u32, bytes: Vec<u8>, last_error: i32) -> Self {
        let bytes_returned = bytes.len();
        Self {
            status: ReadStatus::Success,
            bytes,
            bytes_returned,
            last_error,
            attributes,
            buffer_too_small: false,
            required_size: 0,
        }
    }

    pub fn failure(bytes_returned: usize, last_error: i32) -> Self {
        Self {
            status: ReadStatus::Error,
            bytes: Vec::new(),
            bytes_returned,
            last_error,
            attributes: 0,
            buffer_too_small: false,
            required_size: 0,
        }
    }

    pub fn missing(last_error: i32) -> Self {
        Self::missing_with_attributes(last_error, 0)
    }

    pub fn missing_with_attributes(last_error: i32, attributes: u32) -> Self {
        Self {
            status: ReadStatus::Missing,
            bytes: Vec::new(),
            bytes_returned: 0,
            last_error,
            attributes,
            buffer_too_small: false,
            required_size: 0,
        }
    }

    pub fn buffer_too_small(required_size: usize, attributes: u32) -> Self {
        Self {
            status: ReadStatus::Error,
            bytes: Vec::new(),
            bytes_returned: 0,
            last_error: 122,
            attributes,
            buffer_too_small: true,
            required_size,
        }
    }

    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes_returned = bytes.len();
        self.bytes = bytes;
        self
    }
}

/// Injectable native boundary.  Names and attributes remain closed at this
/// layer; callers cannot provide a native string or GUID.
pub trait WindowsCalls {
    fn firmware_type(&mut self) -> Result<FirmwareType, CallError>;
    fn read_variable(&mut self, variable: VariableName, buffer_size: usize) -> ReadOutcome;
    /// The native name, GUID, attributes, and payload length are fixed by
    /// this boundary. Only the already-serialized two-byte BootNext value is
    /// passed to the call implementation.
    fn write_boot_next(&mut self, payload: [u8; 2]) -> Result<(), CallError>;
}

pub fn check_environment<C: WindowsCalls>(calls: &mut C) -> Result<(), Error> {
    match calls.firmware_type() {
        Ok(FirmwareType::Uefi) => Ok(()),
        Ok(FirmwareType::Bios | FirmwareType::Unknown(_)) => Err(Error::NotUefi),
        Err(error) => Err(Error::FirmwareReadFailed {
            raw_code: error.raw_code,
        }),
    }
}

#[derive(Debug)]
enum ReadFailure {
    Missing(ReadOutcome),
    Error(ReadOutcome),
    ResourceLimit,
}

fn read_bounded<C: WindowsCalls>(
    calls: &mut C,
    variable: VariableName,
    total: &mut usize,
) -> Result<ReadOutcome, ReadFailure> {
    let mut buffer_size = INITIAL_BUFFER_BYTES;
    loop {
        let outcome = calls.read_variable(variable, buffer_size);
        if outcome.buffer_too_small {
            if outcome.required_size <= buffer_size || outcome.required_size > MAX_VARIABLE_BYTES {
                return Err(ReadFailure::ResourceLimit);
            }
            buffer_size = outcome.required_size;
            continue;
        }
        match outcome.status {
            ReadStatus::Success => {
                if outcome.bytes_returned != outcome.bytes.len()
                    || outcome.bytes_returned > buffer_size
                {
                    return Err(ReadFailure::ResourceLimit);
                }
                let charged = outcome
                    .bytes
                    .len()
                    .checked_add(std::mem::size_of::<u32>())
                    .ok_or(ReadFailure::ResourceLimit)?;
                if charged > MAX_VARIABLE_BYTES {
                    return Err(ReadFailure::ResourceLimit);
                }
                *total = total
                    .checked_add(charged)
                    .filter(|total| *total <= MAX_RAW_INVENTORY_BYTES)
                    .ok_or(ReadFailure::ResourceLimit)?;
                return Ok(outcome);
            }
            ReadStatus::Missing => return Err(ReadFailure::Missing(outcome)),
            ReadStatus::Error => return Err(ReadFailure::Error(outcome)),
        }
    }
}

fn map_control_read_failure(failure: ReadFailure) -> Error {
    match failure {
        ReadFailure::Missing(outcome) => Error::FirmwareReadFailed {
            raw_code: outcome.last_error,
        },
        ReadFailure::Error(outcome) => Error::FirmwareReadFailed {
            raw_code: outcome.last_error,
        },
        ReadFailure::ResourceLimit => Error::ResourceLimit,
    }
}

#[cfg(any(windows, test))]
fn map_native_read_error(variable: VariableName, raw_code: i32) -> ReadOutcome {
    if raw_code == ERROR_ENVVAR_NOT_FOUND
        && matches!(variable, VariableName::BootNext | VariableName::Boot(_))
    {
        ReadOutcome::missing(raw_code)
    } else {
        ReadOutcome::failure(0, raw_code)
    }
}

fn payload(outcome: &ReadOutcome, expected_attributes: u32) -> Result<&[u8], Error> {
    if outcome.attributes != expected_attributes {
        return Err(Error::UnsupportedFormat);
    }
    Ok(&outcome.bytes)
}

fn decode_id(bytes: &[u8]) -> Result<BootId, Error> {
    let pair: [u8; 2] = bytes.try_into().map_err(|_| Error::UnsupportedFormat)?;
    Ok(BootId(u16::from_le_bytes(pair)))
}

pub fn read_next<C: WindowsCalls>(calls: &mut C) -> Result<Option<BootId>, Error> {
    let mut total = 0;
    let outcome = match read_bounded(calls, VariableName::BootNext, &mut total) {
        Ok(outcome) => outcome,
        Err(ReadFailure::Missing(_outcome)) => return Ok(None),
        Err(ReadFailure::Error(outcome)) => {
            return Err(Error::FirmwareReadFailed {
                raw_code: outcome.last_error,
            });
        }
        Err(ReadFailure::ResourceLimit) => return Err(Error::ResourceLimit),
    };
    decode_id(payload(&outcome, BOOT_ATTRIBUTES)?).map(Some)
}

pub fn read_options<C: WindowsCalls>(calls: &mut C) -> Result<OptionInventory, Error> {
    let mut total = 0;
    let order = match read_bounded(calls, VariableName::BootOrder, &mut total) {
        Ok(outcome) => outcome,
        Err(error) => return Err(map_control_read_failure(error)),
    };
    let order = payload(&order, BOOT_ATTRIBUTES)?;
    if order.is_empty() || !order.len().is_multiple_of(2) {
        return Err(Error::UnsupportedFormat);
    }

    let mut referenced = [false; 65_536];
    let mut duplicate = [false; 65_536];
    let mut ids = Vec::new();
    let mut diagnostics = Vec::new();
    for pair in order.as_chunks::<2>().0 {
        let id = u16::from_le_bytes([pair[0], pair[1]]);
        let index = usize::from(id);
        if referenced[index] && !duplicate[index] {
            diagnostics.push(EnumerationDiagnostic::DuplicateBootOrder(BootId(id)));
            duplicate[index] = true;
        }
        if !referenced[index] {
            referenced[index] = true;
            ids.push(BootId(id));
        }
    }

    let current = match read_bounded(calls, VariableName::BootCurrent, &mut total) {
        Ok(outcome) => outcome,
        Err(error) => return Err(map_control_read_failure(error)),
    };
    let current = decode_id(payload(&current, BOOT_CURRENT_ATTRIBUTES)?)?;
    if !referenced[usize::from(current.0)] {
        ids.push(current);
    }

    let mut entries = Vec::with_capacity(ids.len());
    for id in ids {
        let outcome = match read_bounded(calls, VariableName::Boot(id), &mut total) {
            Ok(outcome) => outcome,
            Err(ReadFailure::Missing(_)) => return Err(Error::TargetMissing),
            Err(ReadFailure::Error(outcome)) => {
                return Err(Error::FirmwareReadFailed {
                    raw_code: outcome.last_error,
                });
            }
            Err(ReadFailure::ResourceLimit) => return Err(Error::ResourceLimit),
        };
        let bytes = payload(&outcome, BOOT_ATTRIBUTES)?;
        let option = parse_load_option(bytes)?;
        entries.push((id, option));
    }
    Ok(OptionInventory {
        entries,
        diagnostics,
    })
}

/// Typed BootNext writer used by the later platform adapter.  It is crate
/// private so no caller can choose a native name, GUID, or deletion operation.
#[allow(dead_code)]
pub(crate) fn set_boot_next<C: WindowsCalls>(calls: &mut C, target: BootId) -> Result<(), Error> {
    calls
        .write_boot_next(target.0.to_le_bytes())
        .map_err(|error| Error::FirmwareWriteFailed {
            raw_code: error.raw_code,
        })
}

#[cfg(windows)]
#[allow(dead_code)]
pub(crate) mod native {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
    use windows_sys::Win32::System::SystemInformation::{
        FIRMWARE_TYPE, FirmwareTypeBios as FIRMWARE_TYPE_BIOS,
        FirmwareTypeUefi as FIRMWARE_TYPE_UEFI, FirmwareTypeUnknown as FIRMWARE_TYPE_UNKNOWN,
        GetFirmwareType,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        GetFirmwareEnvironmentVariableExW, SetFirmwareEnvironmentVariableExW,
    };

    const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
    const ERROR_INVALID_DATA: i32 = 13;

    /// The native adapter has no public constructor. The helper production
    /// entry point will be the sole owner allowed to instantiate it.
    #[allow(dead_code)]
    pub(crate) struct SystemWindowsCalls {
        token: NativeTokenCalls,
    }

    impl SystemWindowsCalls {
        #[allow(dead_code)]
        pub(crate) fn new() -> Self {
            Self {
                token: NativeTokenCalls::new(),
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn native_error(error: &Error) -> i32 {
        match error {
            Error::PrivilegeEnableFailed { raw_code }
            | Error::PrivilegeRestoreFailed { raw_code }
            | Error::FirmwareReadFailed { raw_code }
            | Error::FirmwareWriteFailed { raw_code }
            | Error::BootNextUnavailable { raw_code }
            | Error::ProtectedStoreViolation { raw_code }
            | Error::StoreReplaceFailed { raw_code }
            | Error::StoreDurabilityUnknown { raw_code }
            | Error::PlatformIo { raw_code, .. } => *raw_code,
            _ => 1,
        }
    }

    fn read_firmware(
        token: &mut NativeTokenCalls,
        variable: VariableName,
        buffer_size: usize,
    ) -> Result<ReadOutcome, Error> {
        let native_size =
            validate_native_buffer_size(buffer_size).map_err(|_| Error::ResourceLimit)?;
        let name = wide(&variable.to_string());
        let guid = wide(GLOBAL_VARIABLE_GUID);
        with_system_environment_privilege(token, |_| {
            let mut bytes = vec![0u8; buffer_size];
            let mut attributes = 0u32;
            // SetLastError is required because a zero return is the only
            // failure signal and the error must be captured immediately.
            unsafe { SetLastError(0) };
            let returned = unsafe {
                GetFirmwareEnvironmentVariableExW(
                    name.as_ptr(),
                    guid.as_ptr(),
                    bytes.as_mut_ptr().cast::<c_void>(),
                    native_size,
                    &mut attributes,
                )
            };
            let last_error = unsafe { GetLastError() as i32 };
            if returned == 0 {
                if last_error == ERROR_INSUFFICIENT_BUFFER {
                    let required_size = if buffer_size >= MAX_VARIABLE_BYTES {
                        MAX_VARIABLE_BYTES + 1
                    } else {
                        buffer_size.saturating_mul(2).min(MAX_VARIABLE_BYTES)
                    };
                    return Ok(ReadOutcome::buffer_too_small(required_size, attributes));
                }
                return Ok(map_native_read_error(variable, last_error));
            }
            Ok(successful_native_read(
                returned,
                buffer_size,
                attributes,
                last_error,
                bytes,
            ))
        })
    }

    fn successful_native_read(
        returned: u32,
        buffer_size: usize,
        attributes: u32,
        last_error: i32,
        mut bytes: Vec<u8>,
    ) -> ReadOutcome {
        let returned = returned as usize;
        if returned > buffer_size || returned > bytes.len() {
            return ReadOutcome::failure(returned, ERROR_INVALID_DATA);
        }
        bytes.truncate(returned);
        ReadOutcome::success_with_last_error(attributes, bytes, last_error)
    }

    fn native_set_boot_next(
        token: &mut NativeTokenCalls,
        payload: [u8; 2],
    ) -> Result<(), CallError> {
        let name = wide("BootNext");
        let guid = wide(GLOBAL_VARIABLE_GUID);
        with_system_environment_privilege(token, |_| {
            // This is the only SetFirmwareEnvironmentVariableExW call in the
            // crate. A fixed two-byte payload cannot delete a variable.
            unsafe { SetLastError(0) };
            let success = unsafe {
                SetFirmwareEnvironmentVariableExW(
                    name.as_ptr(),
                    guid.as_ptr(),
                    payload.as_ptr().cast::<c_void>(),
                    payload.len() as u32,
                    BOOT_ATTRIBUTES,
                )
            };
            let last_error = unsafe { GetLastError() as i32 };
            if success == 0 {
                Err(Error::FirmwareWriteFailed {
                    raw_code: last_error,
                })
            } else {
                Ok(())
            }
        })
        .map_err(|error| CallError::new(native_error(&error)))
    }

    impl WindowsCalls for SystemWindowsCalls {
        fn firmware_type(&mut self) -> Result<FirmwareType, CallError> {
            let mut firmware_type: FIRMWARE_TYPE = FIRMWARE_TYPE_UNKNOWN;
            unsafe { SetLastError(0) };
            let success = unsafe { GetFirmwareType(&mut firmware_type) };
            let last_error = unsafe { GetLastError() as i32 };
            if success == 0 {
                return Err(CallError::new(last_error));
            }
            Ok(match firmware_type {
                FIRMWARE_TYPE_UEFI => FirmwareType::Uefi,
                FIRMWARE_TYPE_BIOS => FirmwareType::Bios,
                other => FirmwareType::Unknown(other as u32),
            })
        }

        fn read_variable(&mut self, variable: VariableName, buffer_size: usize) -> ReadOutcome {
            match read_firmware(&mut self.token, variable, buffer_size) {
                Ok(outcome) => outcome,
                Err(error) => ReadOutcome::failure(0, native_error(&error)),
            }
        }

        fn write_boot_next(&mut self, payload: [u8; 2]) -> Result<(), CallError> {
            native_set_boot_next(&mut self.token, payload)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::successful_native_read;
        use crate::windows::firmware::ReadStatus;

        #[test]
        fn success_count_larger_than_buffer_is_rejected_without_truncation() {
            let outcome = successful_native_read(9, 8, 7, 0, vec![0; 8]);
            assert_eq!(outcome.status, ReadStatus::Error);
            assert_eq!(outcome.bytes_returned, 9);
            assert!(outcome.bytes.is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_203_is_missing_only_for_bootnext_and_boot_entries() {
        for variable in [VariableName::BootNext, VariableName::Boot(BootId(3))] {
            let outcome = map_native_read_error(variable, ERROR_ENVVAR_NOT_FOUND);
            assert_eq!(outcome.status, ReadStatus::Missing);
            assert_eq!(outcome.last_error, ERROR_ENVVAR_NOT_FOUND);
        }
        for variable in [VariableName::BootOrder, VariableName::BootCurrent] {
            let outcome = map_native_read_error(variable, ERROR_ENVVAR_NOT_FOUND);
            assert_eq!(outcome.status, ReadStatus::Error);
            assert_eq!(outcome.last_error, ERROR_ENVVAR_NOT_FOUND);
        }
        for variable in [VariableName::BootNext, VariableName::Boot(BootId(3))] {
            let outcome = map_native_read_error(variable, 5);
            assert_eq!(outcome.status, ReadStatus::Error);
            assert_eq!(outcome.last_error, 5);
        }
    }

    struct Writer {
        calls: Vec<(VariableName, Vec<u8>, u32)>,
        result: Result<(), CallError>,
    }

    impl WindowsCalls for Writer {
        fn firmware_type(&mut self) -> Result<FirmwareType, CallError> {
            Ok(FirmwareType::Uefi)
        }

        fn read_variable(&mut self, _: VariableName, _: usize) -> ReadOutcome {
            ReadOutcome::failure(0, 5)
        }

        fn write_boot_next(&mut self, payload: [u8; 2]) -> Result<(), CallError> {
            self.calls
                .push((VariableName::BootNext, payload.to_vec(), BOOT_ATTRIBUTES));
            self.result
        }
    }

    #[test]
    fn set_boot_next_is_exactly_typed_little_endian_and_single_call() {
        let mut calls = Writer {
            calls: Vec::new(),
            result: Ok(()),
        };
        assert_eq!(set_boot_next(&mut calls, BootId(0x1234)), Ok(()));
        assert_eq!(
            calls.calls,
            [(VariableName::BootNext, vec![0x34, 0x12], BOOT_ATTRIBUTES)]
        );
    }

    #[test]
    fn set_boot_next_preserves_the_immediate_write_error_without_retry() {
        let mut calls = Writer {
            calls: Vec::new(),
            result: Err(CallError::new(122)),
        };
        assert_eq!(
            set_boot_next(&mut calls, BootId(3)),
            Err(Error::FirmwareWriteFailed { raw_code: 122 })
        );
        assert_eq!(calls.calls.len(), 1);
    }

    #[test]
    fn malformed_bounded_results_fail_before_parsing_or_budget_accounting() {
        struct Reader(ReadOutcome);
        impl WindowsCalls for Reader {
            fn firmware_type(&mut self) -> Result<FirmwareType, CallError> {
                Ok(FirmwareType::Uefi)
            }
            fn read_variable(&mut self, _: VariableName, _: usize) -> ReadOutcome {
                self.0.clone()
            }
            fn write_boot_next(&mut self, _: [u8; 2]) -> Result<(), CallError> {
                Ok(())
            }
        }

        let mut truncated = Reader(ReadOutcome {
            bytes_returned: 1,
            ..ReadOutcome::success(7, vec![1, 2])
        });
        assert_eq!(read_next(&mut truncated), Err(Error::ResourceLimit));

        let mut non_increasing = Reader(ReadOutcome::buffer_too_small(4096, 7));
        assert_eq!(read_next(&mut non_increasing), Err(Error::ResourceLimit));
    }
}
