use boothop_core::BootId;
use boothop_platform::windows::{
    CallError, FirmwareType, ReadOutcome, ReadStatus, VariableName, WindowsCalls,
};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct FakeWindowsCalls {
    pub firmware: Result<FirmwareType, CallError>,
    pub values: HashMap<VariableName, ReadOutcome>,
    pub scripted: HashMap<VariableName, Vec<ReadOutcome>>,
    pub reads: Vec<(VariableName, usize)>,
    pub writes: Vec<[u8; 2]>,
}

impl FakeWindowsCalls {
    pub fn uefi() -> Self {
        Self {
            firmware: Ok(FirmwareType::Uefi),
            values: HashMap::new(),
            scripted: HashMap::new(),
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    pub fn set(&mut self, variable: VariableName, outcome: ReadOutcome) {
        self.values.insert(variable, outcome);
    }

    pub fn script(&mut self, variable: VariableName, outcomes: Vec<ReadOutcome>) {
        self.scripted.insert(variable, outcomes);
    }

    pub fn read_count(&self, variable: VariableName) -> usize {
        self.reads
            .iter()
            .filter(|(name, _)| *name == variable)
            .count()
    }
}

impl WindowsCalls for FakeWindowsCalls {
    fn firmware_type(&mut self) -> Result<FirmwareType, CallError> {
        self.firmware
    }

    fn read_variable(&mut self, variable: VariableName, buffer_size: usize) -> ReadOutcome {
        self.reads.push((variable, buffer_size));
        if let Some(outcomes) = self.scripted.get_mut(&variable)
            && !outcomes.is_empty()
        {
            return outcomes.remove(0);
        }
        self.values
            .get(&variable)
            .cloned()
            .unwrap_or_else(|| ReadOutcome::missing(203))
    }

    fn write_boot_next(&mut self, payload: [u8; 2]) -> Result<(), CallError> {
        self.writes.push(payload);
        Ok(())
    }
}

pub fn success(attributes: u32, bytes: Vec<u8>) -> ReadOutcome {
    ReadOutcome::success(attributes, bytes)
}

pub fn id(id: u16) -> Vec<u8> {
    id.to_le_bytes().to_vec()
}

pub fn order(ids: &[u16]) -> Vec<u8> {
    ids.iter().flat_map(|id| id.to_le_bytes()).collect()
}

pub fn option_payload() -> Vec<u8> {
    let hex = include_str!("../../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub fn install_inventory(calls: &mut FakeWindowsCalls, ids: &[u16]) {
    calls.set(VariableName::BootOrder, success(7, order(ids)));
    calls.set(VariableName::BootCurrent, success(6, id(ids[0])));
    for id in ids {
        calls.set(
            VariableName::Boot(BootId(*id)),
            success(7, option_payload()),
        );
    }
}

#[allow(dead_code)]
pub fn error(raw_code: i32) -> ReadOutcome {
    ReadOutcome::failure(0, raw_code)
}

#[allow(dead_code)]
pub fn malformed(status: ReadStatus, bytes: Vec<u8>) -> ReadOutcome {
    ReadOutcome {
        status,
        bytes_returned: bytes.len(),
        bytes,
        last_error: 0,
        attributes: 7,
        buffer_too_small: false,
        required_size: 0,
    }
}
