use boothop_core::BootId;

pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
pub const MAX_SUMMARY_BYTES: usize = 160;
pub const INITIAL_BUFFER_BYTES: usize = 4_096;
pub const MAX_ENUMERATION_BYTES: usize = MAX_PAYLOAD_BYTES;

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
pub struct PrivilegeState {
    pub was_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallError {
    pub raw_code: u32,
}
impl CallError {
    pub const fn new(raw_code: u32) -> Self {
        Self { raw_code }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadStatus {
    Success,
    Missing,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOutcome {
    pub status: ReadStatus,
    pub bytes: Vec<u8>,
    pub bytes_returned: usize,
    pub last_error: u32,
    pub attributes: u32,
    pub buffer_too_small: bool,
    pub required_size: usize,
}

impl ReadOutcome {
    pub fn success(attributes: u32, bytes: Vec<u8>) -> Self {
        Self::success_with_last_error(attributes, bytes, 0)
    }

    pub fn success_with_last_error(attributes: u32, bytes: Vec<u8>, last_error: u32) -> Self {
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
    pub fn failure(bytes_returned: usize, last_error: u32) -> Self {
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
    pub fn missing(last_error: u32) -> Self {
        Self::missing_with_attributes(last_error, 0)
    }

    pub fn missing_with_attributes(last_error: u32, attributes: u32) -> Self {
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

pub trait WindowsCalls {
    fn firmware_type(&mut self) -> Result<FirmwareType, CallError>;
    fn enable_privilege(&mut self) -> Result<PrivilegeState, CallError>;
    fn restore_privilege(&mut self, state: PrivilegeState) -> Result<(), CallError>;
    fn read_variable(&mut self, variable: VariableName, buffer_size: usize) -> ReadOutcome;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Args {
    run_id: String,
}

impl Args {
    pub(crate) fn new(run_id: String) -> Self {
        Self { run_id }
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[cfg(test)]
    pub(crate) fn forged_for_test(run_id: &str) -> Self {
        Self {
            run_id: run_id.to_owned(),
        }
    }
}
