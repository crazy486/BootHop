use std::collections::HashMap;

use boothop_core::BootId;
use boothop_windows1w_collector::{
    CallError, FirmwareType, PrivilegeState, ReadOutcome, VariableName, WindowsCalls,
};

pub struct FakeCalls {
    pub firmware: Result<FirmwareType, CallError>,
    pub log: Vec<String>,
    pub restored: Option<PrivilegeState>,
    pub restore_error: Option<CallError>,
    pub boot_order: ReadOutcome,
    pub boot_current: ReadOutcome,
    pub boot_next: ReadOutcome,
    pub options: HashMap<BootId, Vec<u8>>,
    pub attrs: HashMap<VariableName, u32>,
    pub resize_boot_order: Option<usize>,
    pub second_order: Option<Vec<u8>>,
    order_reads: usize,
}

impl FakeCalls {
    pub fn new(firmware: FirmwareType) -> Self {
        Self {
            firmware: Ok(firmware),
            log: Vec::new(),
            restored: None,
            restore_error: None,
            boot_order: ReadOutcome::success(7, vec![1, 0]),
            boot_current: ReadOutcome::success(6, vec![1, 0]),
            boot_next: ReadOutcome::success(7, vec![1, 0]),
            options: [(BootId(1), load_option_bytes())].into_iter().collect(),
            attrs: HashMap::new(),
            resize_boot_order: None,
            second_order: None,
            order_reads: 0,
        }
    }

    pub fn minimal_valid() -> Self {
        Self::new(FirmwareType::Uefi)
    }

    pub fn with_firmware_error(code: i32) -> Self {
        let mut fake = Self::new(FirmwareType::Uefi);
        fake.firmware = Err(CallError::new(code));
        fake
    }

    pub fn set_attributes(&mut self, variable: VariableName, attributes: u32) {
        self.attrs.insert(variable, attributes);
    }

    pub fn read_count(&self, variable: VariableName) -> usize {
        self.log
            .iter()
            .filter(|entry| entry.as_str() == format!("read {variable}"))
            .count()
    }
}

impl WindowsCalls for FakeCalls {
    fn firmware_type(&mut self) -> Result<FirmwareType, CallError> {
        self.log.push("firmware_type".into());
        self.firmware.clone()
    }

    fn enable_privilege(&mut self) -> Result<PrivilegeState, CallError> {
        self.log.push("enable_privilege".into());
        Ok(PrivilegeState { was_enabled: false })
    }

    fn restore_privilege(&mut self, state: PrivilegeState) -> Result<(), CallError> {
        self.log.push("restore".into());
        self.restored = Some(state);
        self.restore_error.clone().map_or(Ok(()), Err)
    }

    fn read_variable(&mut self, variable: VariableName, buffer_size: usize) -> ReadOutcome {
        self.log.push(format!("read {variable}"));
        let mut outcome = match variable {
            VariableName::BootOrder => {
                self.order_reads += 1;
                let bytes = self
                    .second_order
                    .clone()
                    .filter(|_| self.order_reads > 1)
                    .unwrap_or_else(|| self.boot_order.bytes.clone());
                self.boot_order.clone().with_bytes(bytes)
            }
            VariableName::BootCurrent => self.boot_current.clone(),
            VariableName::BootNext => self.boot_next.clone(),
            VariableName::Boot(id) => {
                self.options
                    .get(&id)
                    .cloned()
                    .map_or(ReadOutcome::failure(2, 2), |bytes| {
                        ReadOutcome::success(self.attrs.get(&variable).copied().unwrap_or(7), bytes)
                    })
            }
        };
        if let Some(attributes) = self.attrs.get(&variable).copied() {
            outcome.attributes = attributes;
        }
        if variable == VariableName::BootOrder
            && let Some(required) = self.resize_boot_order
            && buffer_size < required
        {
            return ReadOutcome::buffer_too_small(required, outcome.attributes);
        }
        outcome
    }
}

pub fn load_option_bytes() -> Vec<u8> {
    let mut bytes = vec![1, 0, 0, 0, 4, 0];
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[0x7f, 0xff, 4, 0]);
    bytes
}
