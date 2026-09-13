use crate::{
    CallError, FirmwareType, PrivilegeState, ReadOutcome, VariableName, WindowsCalls,
    evidence::{Attempt, Evidence, OptionEvidence, attempt},
    model::{INITIAL_BUFFER_BYTES, MAX_PAYLOAD_BYTES},
};
use boothop_core::{BootId, parse_load_option};
use std::collections::HashSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectorError {
    FirmwareType {
        raw_code: i32,
    },
    NonUefi(FirmwareType),
    PrivilegeEnable {
        raw_code: i32,
    },
    RestorePrivilege {
        raw_code: i32,
    },
    Read {
        variable: VariableName,
        raw_code: u32,
    },
    InvalidAttributes {
        variable: VariableName,
        expected: u32,
        actual: u32,
    },
    MalformedControl {
        variable: VariableName,
    },
    MissingReferencedOption {
        boot_id: BootId,
        raw_code: u32,
    },
    InvalidReferencedOption(BootId),
    ResourceLimit,
    Unstable,
}

pub fn collect_with<C: WindowsCalls>(calls: &mut C) -> Result<Evidence, CollectorError> {
    match calls.firmware_type() {
        Ok(FirmwareType::Uefi) => {}
        Ok(kind) => return Err(CollectorError::NonUefi(kind)),
        Err(error) => {
            return Err(CollectorError::FirmwareType {
                raw_code: error.raw_code,
            });
        }
    }
    let privilege = calls
        .enable_privilege()
        .map_err(|error| CollectorError::PrivilegeEnable {
            raw_code: error.raw_code,
        })?;
    let result = collect_after_privilege(calls, privilege);
    match calls.restore_privilege(privilege) {
        Ok(()) => result,
        Err(error) => Err(CollectorError::RestorePrivilege {
            raw_code: error.raw_code,
        }),
    }
}

fn collect_after_privilege<C: WindowsCalls>(
    calls: &mut C,
    _privilege: PrivilegeState,
) -> Result<Evidence, CollectorError> {
    let mut attempts = Vec::new();
    let first = read_controls(calls, &mut attempts)?;
    let mut option_ids = Vec::new();
    let mut seen = HashSet::new();
    for id in first
        .boot_order
        .iter()
        .chain(std::iter::once(&first.boot_current))
        .chain(first.boot_next.iter())
        .copied()
    {
        if seen.insert(id) {
            option_ids.push(id);
        }
    }
    let mut options = Vec::new();
    for id in option_ids.iter().copied() {
        let outcome = match read_bounded(calls, VariableName::Boot(id), &mut attempts) {
            Ok(outcome) => outcome,
            Err(CollectorError::Read {
                variable: VariableName::Boot(_),
                raw_code: 2,
            }) => {
                return Err(CollectorError::MissingReferencedOption {
                    boot_id: id,
                    raw_code: 2,
                });
            }
            Err(error) => return Err(error),
        };
        if outcome.attributes != 7 {
            return Err(CollectorError::InvalidAttributes {
                variable: VariableName::Boot(id),
                expected: 7,
                actual: outcome.attributes,
            });
        }
        let parsed = parse_load_option(&outcome.bytes)
            .map_err(|_| CollectorError::InvalidReferencedOption(id))?;
        options.push(OptionEvidence {
            boot_id: id,
            raw_payload: outcome.bytes,
            parsed,
        });
    }
    let second = read_controls(calls, &mut attempts)?;
    let stable = first == second;
    Ok(Evidence {
        attempts,
        options,
        option_ids,
        stable,
        accepted: stable,
        boot_next_absent: false,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Controls {
    boot_order: Vec<BootId>,
    boot_current: BootId,
    boot_next: Option<BootId>,
}

fn read_controls<C: WindowsCalls>(
    calls: &mut C,
    attempts: &mut Vec<Attempt>,
) -> Result<Controls, CollectorError> {
    let order = read_bounded(calls, VariableName::BootOrder, attempts)?;
    require_attributes(VariableName::BootOrder, order.attributes, 7)?;
    let boot_order = decode_order(&order.bytes).ok_or(CollectorError::MalformedControl {
        variable: VariableName::BootOrder,
    })?;
    let current = read_bounded(calls, VariableName::BootCurrent, attempts)?;
    require_attributes(VariableName::BootCurrent, current.attributes, 6)?;
    let boot_current = decode_single(&current.bytes, VariableName::BootCurrent)?;
    let boot_next = match read_bounded(calls, VariableName::BootNext, attempts) {
        Ok(outcome) => {
            require_attributes(VariableName::BootNext, outcome.attributes, 7)?;
            Some(decode_single(&outcome.bytes, VariableName::BootNext)?)
        }
        Err(CollectorError::Read { .. }) => None,
        Err(error) => return Err(error),
    };
    Ok(Controls {
        boot_order,
        boot_current,
        boot_next,
    })
}

fn read_bounded<C: WindowsCalls>(
    calls: &mut C,
    variable: VariableName,
    attempts: &mut Vec<Attempt>,
) -> Result<ReadOutcome, CollectorError> {
    let mut buffer_size = INITIAL_BUFFER_BYTES;
    loop {
        let outcome = calls.read_variable(variable, buffer_size);
        attempts.push(attempt(
            variable,
            outcome.success,
            outcome.bytes_returned,
            outcome.last_error,
            outcome.attributes,
            &outcome.bytes,
            outcome.buffer_too_small,
        ));
        if outcome.buffer_too_small {
            if outcome.required_size <= buffer_size || outcome.required_size > MAX_PAYLOAD_BYTES {
                return Err(CollectorError::ResourceLimit);
            }
            buffer_size = outcome.required_size;
            continue;
        }
        if outcome.success {
            if outcome.bytes.len() > MAX_PAYLOAD_BYTES
                || outcome.bytes_returned != outcome.bytes.len()
            {
                return Err(CollectorError::ResourceLimit);
            }
            return Ok(outcome);
        }
        return Err(CollectorError::Read {
            variable,
            raw_code: outcome.last_error,
        });
    }
}

fn require_attributes(
    variable: VariableName,
    actual: u32,
    expected: u32,
) -> Result<(), CollectorError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CollectorError::InvalidAttributes {
            variable,
            expected,
            actual,
        })
    }
}
fn decode_order(bytes: &[u8]) -> Option<Vec<BootId>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| BootId(u16::from_le_bytes([pair[0], pair[1]])))
            .collect(),
    )
}
fn decode_single(bytes: &[u8], variable: VariableName) -> Result<BootId, CollectorError> {
    let pair: [u8; 2] = bytes
        .try_into()
        .map_err(|_| CollectorError::MalformedControl { variable })?;
    Ok(BootId(u16::from_le_bytes(pair)))
}
impl From<CallError> for CollectorError {
    fn from(error: CallError) -> Self {
        Self::FirmwareType {
            raw_code: error.raw_code,
        }
    }
}
