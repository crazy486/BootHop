use boothop_core::BootId;

pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
pub const MAX_SUMMARY_BYTES: usize = 160;
pub const INITIAL_BUFFER_BYTES: usize = 4_096;

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
    pub raw_code: i32,
}
impl CallError {
    pub const fn new(raw_code: i32) -> Self {
        Self { raw_code }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOutcome {
    pub success: bool,
    pub bytes: Vec<u8>,
    pub bytes_returned: usize,
    pub last_error: u32,
    pub attributes: u32,
    pub buffer_too_small: bool,
    pub required_size: usize,
}

impl ReadOutcome {
    pub fn success(attributes: u32, bytes: Vec<u8>) -> Self {
        let bytes_returned = bytes.len();
        Self {
            success: true,
            bytes,
            bytes_returned,
            last_error: 0,
            attributes,
            buffer_too_small: false,
            required_size: 0,
        }
    }
    pub fn failure(bytes_returned: usize, last_error: u32) -> Self {
        Self {
            success: false,
            bytes: Vec::new(),
            bytes_returned,
            last_error,
            attributes: 0,
            buffer_too_small: false,
            required_size: 0,
        }
    }
    pub fn buffer_too_small(required_size: usize, attributes: u32) -> Self {
        Self {
            success: false,
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
    pub run_id: String,
}
