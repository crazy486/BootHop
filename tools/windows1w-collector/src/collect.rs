use std::collections::HashSet;

use boothop_core::{BootId, parse_load_option};

use crate::{
    FirmwareType, MAX_ENUMERATION_BYTES, PrivilegeState, ReadOutcome, ReadStatus, VariableName,
    WindowsCalls,
    evidence::{
        Attempt, ControlSnapshot, ControlValue, Evidence, OptionEvidence, TerminalOutcome, attempt,
        digest,
    },
    model::{INITIAL_BUFFER_BYTES, MAX_PAYLOAD_BYTES},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectorError {
    FirmwareType {
        raw_code: u32,
    },
    NonUefi(FirmwareType),
    PrivilegeEnable {
        raw_code: u32,
    },
    RestorePrivilege {
        raw_code: u32,
    },
    Read {
        variable: VariableName,
        raw_code: u32,
    },
    Missing {
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
}

impl CollectorError {
    pub fn raw_code(&self) -> Option<u32> {
        match self {
            Self::FirmwareType { raw_code }
            | Self::PrivilegeEnable { raw_code }
            | Self::RestorePrivilege { raw_code }
            | Self::Read { raw_code, .. }
            | Self::Missing { raw_code, .. }
            | Self::MissingReferencedOption { raw_code, .. } => Some(*raw_code),
            _ => None,
        }
    }

    pub fn variable(&self) -> Option<VariableName> {
        match self {
            Self::Read { variable, .. }
            | Self::Missing { variable, .. }
            | Self::InvalidAttributes { variable, .. }
            | Self::MalformedControl { variable } => Some(*variable),
            _ => None,
        }
    }

    pub fn missing_boot_id(&self) -> Option<BootId> {
        match self {
            Self::MissingReferencedOption { boot_id, .. } => Some(*boot_id),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionFailure {
    pub error: CollectorError,
    pub evidence: Evidence,
}

impl CollectionFailure {
    fn new(error: CollectorError, attempts: Vec<Attempt>) -> Self {
        Self {
            error,
            evidence: Evidence::failed(attempts),
        }
    }

    fn with_state(
        error: CollectorError,
        attempts: Vec<Attempt>,
        options: Vec<OptionEvidence>,
        option_ids: Vec<BootId>,
        first_control: Option<ControlSnapshot>,
        second_control: Option<ControlSnapshot>,
    ) -> Self {
        Self {
            error,
            evidence: Evidence {
                attempts,
                options,
                option_ids,
                stable: false,
                accepted: false,
                boot_next_absent: false,
                terminal: TerminalOutcome::Failed,
                first_control: first_control.map(Box::new),
                second_control: second_control.map(Box::new),
            },
        }
    }
}

pub fn collect_with<C: WindowsCalls>(calls: &mut C) -> Result<Evidence, CollectionFailure> {
    match calls.firmware_type() {
        Ok(FirmwareType::Uefi) => {}
        Ok(kind) => {
            return Err(CollectionFailure::new(
                CollectorError::NonUefi(kind),
                Vec::new(),
            ));
        }
        Err(error) => {
            return Err(CollectionFailure::new(
                CollectorError::FirmwareType {
                    raw_code: error.raw_code,
                },
                Vec::new(),
            ));
        }
    }
    let privilege = match calls.enable_privilege() {
        Ok(state) => state,
        Err(error) => {
            return Err(CollectionFailure::new(
                CollectorError::PrivilegeEnable {
                    raw_code: error.raw_code,
                },
                Vec::new(),
            ));
        }
    };
    let result = collect_after_privilege(calls, privilege);
    match calls.restore_privilege(privilege) {
        Ok(()) => result,
        Err(error) => {
            let mut evidence = match result {
                Ok(evidence) => evidence,
                Err(failure) => failure.evidence,
            };
            evidence.accepted = false;
            evidence.terminal = TerminalOutcome::Failed;
            Err(CollectionFailure {
                error: CollectorError::RestorePrivilege {
                    raw_code: error.raw_code,
                },
                evidence,
            })
        }
    }
}

fn collect_after_privilege<C: WindowsCalls>(
    calls: &mut C,
    _privilege: PrivilegeState,
) -> Result<Evidence, CollectionFailure> {
    let mut attempts = Vec::new();
    let first = match read_controls(calls, &mut attempts) {
        Ok(controls) => controls,
        Err(error) => return Err(CollectionFailure::new(error, attempts)),
    };
    let mut enumeration_bytes = first.enumeration_bytes;
    if enumeration_bytes > MAX_ENUMERATION_BYTES {
        return Err(CollectionFailure::with_state(
            CollectorError::ResourceLimit,
            attempts,
            Vec::new(),
            Vec::new(),
            Some(first.snapshot.clone()),
            None,
        ));
    }
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
            Err(ReadFailure::Missing { outcome }) => {
                return Err(CollectionFailure::with_state(
                    CollectorError::MissingReferencedOption {
                        boot_id: id,
                        raw_code: outcome.last_error,
                    },
                    attempts,
                    options.clone(),
                    option_ids.clone(),
                    Some(first.snapshot.clone()),
                    None,
                ));
            }
            Err(ReadFailure::Error { outcome }) => {
                return Err(CollectionFailure::with_state(
                    CollectorError::Read {
                        variable: VariableName::Boot(id),
                        raw_code: outcome.last_error,
                    },
                    attempts,
                    options.clone(),
                    option_ids.clone(),
                    Some(first.snapshot.clone()),
                    None,
                ));
            }
            Err(ReadFailure::ResourceLimit) => {
                return Err(CollectionFailure::with_state(
                    CollectorError::ResourceLimit,
                    attempts,
                    options.clone(),
                    option_ids.clone(),
                    Some(first.snapshot.clone()),
                    None,
                ));
            }
        };
        if outcome.attributes != 7 {
            return Err(CollectionFailure::with_state(
                CollectorError::InvalidAttributes {
                    variable: VariableName::Boot(id),
                    expected: 7,
                    actual: outcome.attributes,
                },
                attempts,
                options.clone(),
                option_ids.clone(),
                Some(first.snapshot.clone()),
                None,
            ));
        }
        enumeration_bytes = match enumeration_bytes.checked_add(outcome.bytes.len()) {
            Some(total) if total <= MAX_ENUMERATION_BYTES => total,
            _ => {
                return Err(CollectionFailure::with_state(
                    CollectorError::ResourceLimit,
                    attempts,
                    options.clone(),
                    option_ids.clone(),
                    Some(first.snapshot.clone()),
                    None,
                ));
            }
        };
        let parsed = match parse_load_option(&outcome.bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                return Err(CollectionFailure::with_state(
                    CollectorError::InvalidReferencedOption(id),
                    attempts,
                    options,
                    option_ids,
                    Some(first.snapshot.clone()),
                    None,
                ));
            }
        };
        options.push(OptionEvidence {
            boot_id: id,
            raw_payload: outcome.bytes,
            parsed,
        });
    }
    let second = match read_controls(calls, &mut attempts) {
        Ok(controls) => controls,
        Err(error) => {
            return Err(CollectionFailure::with_state(
                error,
                attempts,
                options,
                option_ids,
                Some(first.snapshot.clone()),
                None,
            ));
        }
    };
    let stable = first == second;
    let terminal = if !stable {
        TerminalOutcome::Unstable
    } else if !first.boot_next_available {
        TerminalOutcome::BootNextUnavailable
    } else {
        TerminalOutcome::Accepted
    };
    Ok(Evidence {
        attempts,
        options,
        option_ids,
        stable,
        accepted: terminal == TerminalOutcome::Accepted,
        boot_next_absent: stable && first.boot_next_absent && second.boot_next_absent,
        terminal,
        first_control: Some(Box::new(first.snapshot)),
        second_control: Some(Box::new(second.snapshot)),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Controls {
    boot_order: Vec<BootId>,
    boot_current: BootId,
    boot_next: Option<BootId>,
    observations: Vec<Observation>,
    boot_next_available: bool,
    boot_next_absent: bool,
    enumeration_bytes: usize,
    snapshot: ControlSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Observation {
    variable: VariableName,
    status: ReadStatus,
    bytes_returned: usize,
    last_error: u32,
    attributes: u32,
    digest: String,
}

impl Observation {
    fn from_outcome(variable: VariableName, outcome: &ReadOutcome) -> Self {
        Self {
            variable,
            status: outcome.status,
            bytes_returned: outcome.bytes_returned,
            last_error: outcome.last_error,
            attributes: outcome.attributes,
            digest: digest(&outcome.bytes),
        }
    }
}

fn read_controls<C: WindowsCalls>(
    calls: &mut C,
    attempts: &mut Vec<Attempt>,
) -> Result<Controls, CollectorError> {
    let order = read_bounded(calls, VariableName::BootOrder, attempts)
        .map_err(|error| error.into_collector(VariableName::BootOrder))?;
    let order_observation = Observation::from_outcome(VariableName::BootOrder, &order);
    require_attributes(VariableName::BootOrder, order.attributes, 7)?;
    let boot_order = decode_order(&order.bytes).ok_or(CollectorError::MalformedControl {
        variable: VariableName::BootOrder,
    })?;
    let current = read_bounded(calls, VariableName::BootCurrent, attempts)
        .map_err(|error| error.into_collector(VariableName::BootCurrent))?;
    let current_observation = Observation::from_outcome(VariableName::BootCurrent, &current);
    require_attributes(VariableName::BootCurrent, current.attributes, 6)?;
    let boot_current = decode_single(&current.bytes, VariableName::BootCurrent)?;
    let next = read_bounded(calls, VariableName::BootNext, attempts);
    let (boot_next, boot_next_observation, boot_next_available, boot_next_absent) = match next {
        Ok(outcome) => {
            let observation = Observation::from_outcome(VariableName::BootNext, &outcome);
            require_attributes(VariableName::BootNext, outcome.attributes, 7)?;
            (
                Some(decode_single(&outcome.bytes, VariableName::BootNext)?),
                observation,
                true,
                false,
            )
        }
        Err(ReadFailure::Missing { outcome }) => (
            None,
            Observation::from_outcome(VariableName::BootNext, &outcome),
            false,
            true,
        ),
        Err(ReadFailure::Error { outcome }) => (
            None,
            Observation::from_outcome(VariableName::BootNext, &outcome),
            false,
            false,
        ),
        Err(ReadFailure::ResourceLimit) => return Err(CollectorError::ResourceLimit),
    };
    Ok(Controls {
        boot_order: boot_order.clone(),
        boot_current,
        boot_next,
        observations: vec![
            order_observation,
            current_observation,
            boot_next_observation.clone(),
        ],
        boot_next_available,
        boot_next_absent,
        enumeration_bytes: order.bytes.len() + current.bytes.len(),
        snapshot: ControlSnapshot {
            boot_order: boot_order.clone(),
            boot_order_bytes_returned: order.bytes_returned,
            boot_order_last_error: order.last_error,
            boot_order_attributes: order.attributes,
            boot_order_payload_sha256: digest(&order.bytes),
            boot_current: ControlValue {
                status: current.status,
                value: Some(boot_current),
                bytes_returned: current.bytes_returned,
                last_error: current.last_error,
                attributes: current.attributes,
                payload_sha256: digest(&current.bytes),
            },
            boot_next: ControlValue {
                status: boot_next_observation.status,
                value: boot_next,
                bytes_returned: boot_next_observation.bytes_returned,
                last_error: boot_next_observation.last_error,
                attributes: boot_next_observation.attributes,
                payload_sha256: boot_next_observation.digest.clone(),
            },
            sequential_not_atomic: true,
        },
    })
}

enum ReadFailure {
    Missing { outcome: ReadOutcome },
    Error { outcome: ReadOutcome },
    ResourceLimit,
}
impl ReadFailure {
    fn into_collector(self, variable: VariableName) -> CollectorError {
        match self {
            Self::Missing { outcome } => CollectorError::Missing {
                variable,
                raw_code: outcome.last_error,
            },
            Self::Error { outcome } => CollectorError::Read {
                variable,
                raw_code: outcome.last_error,
            },
            Self::ResourceLimit => CollectorError::ResourceLimit,
        }
    }
}

fn read_bounded<C: WindowsCalls>(
    calls: &mut C,
    variable: VariableName,
    attempts: &mut Vec<Attempt>,
) -> Result<ReadOutcome, ReadFailure> {
    let mut buffer_size = INITIAL_BUFFER_BYTES;
    loop {
        let outcome = calls.read_variable(variable, buffer_size);
        attempts.push(attempt(
            variable,
            outcome.status,
            outcome.bytes_returned,
            outcome.last_error,
            outcome.attributes,
            &outcome.bytes,
            outcome.buffer_too_small,
        ));
        if outcome.buffer_too_small {
            if outcome.required_size <= buffer_size || outcome.required_size > MAX_PAYLOAD_BYTES {
                return Err(ReadFailure::ResourceLimit);
            }
            buffer_size = outcome.required_size;
            continue;
        }
        match outcome.status {
            ReadStatus::Success => {
                if outcome.bytes.len() > MAX_PAYLOAD_BYTES
                    || outcome.bytes_returned != outcome.bytes.len()
                {
                    return Err(ReadFailure::ResourceLimit);
                }
                return Ok(outcome);
            }
            ReadStatus::Missing => {
                return Err(ReadFailure::Missing { outcome });
            }
            ReadStatus::Error => {
                return Err(ReadFailure::Error { outcome });
            }
        }
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
            .map(|pair| BootId(u16::from_le_bytes(*pair)))
            .collect(),
    )
}
fn decode_single(bytes: &[u8], variable: VariableName) -> Result<BootId, CollectorError> {
    let pair: [u8; 2] = bytes
        .try_into()
        .map_err(|_| CollectorError::MalformedControl { variable })?;
    Ok(BootId(u16::from_le_bytes(pair)))
}
