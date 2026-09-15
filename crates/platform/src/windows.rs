//! Portable Windows firmware policy.
//!
//! This module deliberately contains no Win32 imports.  The native call
//! implementation is added behind `windows::native` in a later task; this
//! boundary stays available to host tests and to Windows builds alike.

pub mod firmware;

pub use firmware::{
    BOOT_ATTRIBUTES, BOOT_CURRENT_ATTRIBUTES, CallError, FirmwareType, GLOBAL_VARIABLE_GUID,
    INITIAL_BUFFER_BYTES, MAX_ENUMERATION_BYTES, MAX_PAYLOAD_BYTES, ReadOutcome, ReadStatus,
    VariableName, WindowsCalls, check_environment, read_next, read_options,
};
