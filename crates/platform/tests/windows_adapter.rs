use boothop_core::{
    BootId, Error, Os, Platform, RecordState, Request, TargetRecord, canonicalize, execute,
    parse_load_option,
};
use boothop_platform::ProtectedStore;
use boothop_platform::windows::privilege::{
    ERROR_NOT_ALL_ASSIGNED, Luid, Privilege, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TokenAdjustment,
    TokenCalls, TokenHandle, TokenPrivileges,
};
use boothop_platform::windows::{
    FirmwareType, ReadOutcome, RebootCalls, RebootReply, VariableName, WindowsCalls,
    WindowsPlatform, with_shutdown_privilege,
};
use std::cell::RefCell;
use std::rc::Rc;

struct Store {
    state: RecordState,
    saves: usize,
    events: Option<Rc<RefCell<Vec<&'static str>>>>,
}

impl ProtectedStore for Store {
    fn load(&mut self) -> Result<RecordState, Error> {
        if let Some(events) = &self.events {
            events.borrow_mut().push("load-record");
        }
        Ok(self.state.clone())
    }
    fn save(&mut self, target: &TargetRecord) -> Result<(), Error> {
        if let Some(events) = &self.events {
            events.borrow_mut().push("save-record");
        }
        self.saves += 1;
        self.state = RecordState::Ready(target.clone());
        Ok(())
    }
}

struct Firmware {
    events: Rc<RefCell<Vec<&'static str>>>,
    firmware_type: FirmwareType,
    next: Option<BootId>,
    readback: Option<BootId>,
    next_reads: usize,
    writes: usize,
}

impl WindowsCalls for Firmware {
    fn firmware_type(&mut self) -> Result<FirmwareType, boothop_platform::windows::CallError> {
        self.events.borrow_mut().push("environment");
        Ok(self.firmware_type)
    }
    fn read_variable(&mut self, variable: VariableName, _: usize) -> ReadOutcome {
        self.events.borrow_mut().push(match variable {
            VariableName::BootNext => "read-next",
            VariableName::BootOrder => "read-order",
            VariableName::BootCurrent => "read-current",
            VariableName::Boot(_) => "read-option",
        });
        match variable {
            VariableName::BootOrder => ReadOutcome::success(7, vec![7, 0]),
            VariableName::BootCurrent => ReadOutcome::success(6, vec![7, 0]),
            VariableName::Boot(boot_id) => {
                assert_eq!(boot_id, BootId(7));
                ReadOutcome::success(7, option_payload())
            }
            VariableName::BootNext => {
                self.next_reads += 1;
                let value = if self.next_reads >= 2 {
                    self.readback.or(self.next)
                } else {
                    self.next
                };
                value.map_or_else(
                    || ReadOutcome::missing(203),
                    |id| ReadOutcome::success(7, id.0.to_le_bytes().to_vec()),
                )
            }
        }
    }
    fn write_boot_next(
        &mut self,
        payload: [u8; 2],
    ) -> Result<(), boothop_platform::windows::CallError> {
        self.events.borrow_mut().push("write-next");
        self.writes += 1;
        self.next = Some(BootId(u16::from_le_bytes(payload)));
        Ok(())
    }
}

struct Reboot {
    events: Rc<RefCell<Vec<&'static str>>>,
    reply: RebootReply,
}

struct ShutdownToken {
    lookup: Result<Luid, i32>,
    enable: Result<(), i32>,
    prior: TokenPrivileges,
    adjustments: Vec<TokenPrivileges>,
    closes: usize,
    close_error: Option<i32>,
}

impl TokenCalls for ShutdownToken {
    fn open_process_token(&mut self, access: u32) -> Result<TokenHandle, i32> {
        assert_eq!(access, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY);
        Ok(TokenHandle(9))
    }
    fn lookup_privilege_value(&mut self, privilege: Privilege) -> Result<Luid, i32> {
        assert_eq!(privilege, Privilege::Shutdown);
        self.lookup
    }
    fn set_last_error(&mut self, _: i32) {}
    fn adjust_token_privileges(
        &mut self,
        _: TokenHandle,
        state: &TokenPrivileges,
    ) -> TokenAdjustment {
        self.adjustments.push(state.clone());
        if self.adjustments.len() == 1 {
            TokenAdjustment {
                success: self.enable.is_ok(),
                last_error: self.enable.err().unwrap_or(0),
                previous_state: self.prior.clone(),
                previous_state_valid: true,
            }
        } else {
            TokenAdjustment {
                success: true,
                last_error: 0,
                previous_state: TokenPrivileges::new(Vec::new()),
                previous_state_valid: true,
            }
        }
    }
    fn close_handle(&mut self, _: TokenHandle) -> Result<(), i32> {
        self.closes += 1;
        self.close_error.map_or(Ok(()), Err)
    }
}

impl RebootCalls for Reboot {
    fn request_reboot(&mut self) -> RebootReply {
        self.events.borrow_mut().push("reboot");
        self.reply
    }
}

fn target() -> TargetRecord {
    let option = parse_load_option(&option_payload()).unwrap();
    TargetRecord {
        os: Os::Windows,
        boot_id: BootId(7),
        identity: canonicalize(&option).unwrap(),
    }
}

fn option_payload() -> Vec<u8> {
    let hex = include_str!("../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn inspect_composes_store_environment_and_option_reads_in_order() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut store = Store {
        state: RecordState::Ready(target()),
        saves: 0,
        events: Some(events.clone()),
    };
    let firmware = Firmware {
        events: events.clone(),
        firmware_type: FirmwareType::Uefi,
        next: Some(BootId(7)),
        readback: None,
        next_reads: 0,
        writes: 0,
    };
    let reboot = Reboot {
        events: events.clone(),
        reply: RebootReply::Accepted,
    };
    let mut platform = WindowsPlatform::new(&mut store, firmware, reboot);
    execute(Request::Inspect, Os::Linux, &mut platform).unwrap();
    assert_eq!(
        &*events.borrow(),
        &[
            "load-record",
            "environment",
            "read-order",
            "read-current",
            "read-option"
        ]
    );
}

#[test]
fn configure_saves_only_and_never_writes_or_reboots() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut store = Store {
        state: RecordState::Missing,
        saves: 0,
        events: None,
    };
    let firmware = Firmware {
        events: events.clone(),
        firmware_type: FirmwareType::Uefi,
        next: None,
        readback: None,
        next_reads: 0,
        writes: 0,
    };
    let reboot = Reboot {
        events: events.clone(),
        reply: RebootReply::Accepted,
    };
    let mut platform = WindowsPlatform::new(&mut store, firmware, reboot);

    execute(
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows,
        },
        Os::Linux,
        &mut platform,
    )
    .unwrap();

    assert_eq!(store.saves, 1);
    assert!(!events.borrow().contains(&"write-next"));
    assert!(!events.borrow().contains(&"reboot"));
}

#[test]
fn switch_reads_back_before_reboot_and_maps_acceptance() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut store = Store {
        state: RecordState::Ready(target()),
        saves: 0,
        events: None,
    };
    let firmware = Firmware {
        events: events.clone(),
        firmware_type: FirmwareType::Uefi,
        next: Some(BootId(7)),
        readback: None,
        next_reads: 0,
        writes: 0,
    };
    let reboot = Reboot {
        events: events.clone(),
        reply: RebootReply::Accepted,
    };
    let mut platform = WindowsPlatform::new(&mut store, firmware, reboot);

    let report = execute(
        Request::Switch { os: Os::Windows },
        Os::Linux,
        &mut platform,
    )
    .unwrap();
    assert!(report.stages.contains(&boothop_core::Stage::RebootAccepted));
    let events = events.borrow();
    let readback = events
        .iter()
        .rposition(|event| *event == "read-next")
        .unwrap();
    let reboot = events.iter().position(|event| *event == "reboot").unwrap();
    assert!(readback < reboot);
}

#[test]
fn switch_conflict_stops_before_write_or_reboot() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut store = Store {
        state: RecordState::Ready(target()),
        saves: 0,
        events: None,
    };
    let firmware = Firmware {
        events: events.clone(),
        firmware_type: FirmwareType::Uefi,
        next: Some(BootId(8)),
        readback: None,
        next_reads: 0,
        writes: 0,
    };
    let reboot = Reboot {
        events: events.clone(),
        reply: RebootReply::Accepted,
    };
    let mut platform = WindowsPlatform::new(&mut store, firmware, reboot);

    let error = execute(
        Request::Switch { os: Os::Windows },
        Os::Linux,
        &mut platform,
    )
    .unwrap_err();
    assert!(matches!(error, Error::FlowFailure { cause, .. } if *cause == Error::BootNextConflict));
    assert!(!events.borrow().contains(&"write-next"));
    assert!(!events.borrow().contains(&"reboot"));
}

#[test]
fn switch_readback_mismatch_stops_before_reboot() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut store = Store {
        state: RecordState::Ready(target()),
        saves: 0,
        events: None,
    };
    let firmware = Firmware {
        events: events.clone(),
        firmware_type: FirmwareType::Uefi,
        next: Some(BootId(7)),
        readback: Some(BootId(8)),
        next_reads: 0,
        writes: 0,
    };
    let reboot = Reboot {
        events: events.clone(),
        reply: RebootReply::Accepted,
    };
    let mut platform = WindowsPlatform::new(&mut store, firmware, reboot);

    let error = execute(
        Request::Switch { os: Os::Windows },
        Os::Linux,
        &mut platform,
    )
    .unwrap_err();
    assert!(matches!(error, Error::FlowFailure { cause, .. } if *cause == Error::ReadbackFailed));
    assert!(!events.borrow().contains(&"reboot"));
}

#[test]
fn rejected_and_unknown_reboot_replies_map_without_reordering() {
    for (reply, stage) in [
        (
            RebootReply::Rejected { raw_code: 5 },
            boothop_core::Stage::RebootRejected,
        ),
        (RebootReply::Unknown, boothop_core::Stage::RebootUnknown),
    ] {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut store = Store {
            state: RecordState::Ready(target()),
            saves: 0,
            events: None,
        };
        let firmware = Firmware {
            events: events.clone(),
            firmware_type: FirmwareType::Uefi,
            next: Some(BootId(7)),
            readback: None,
            next_reads: 0,
            writes: 0,
        };
        let reboot = Reboot {
            events: events.clone(),
            reply,
        };
        let mut platform = WindowsPlatform::new(&mut store, firmware, reboot);
        let result = execute(
            Request::Switch { os: Os::Windows },
            Os::Linux,
            &mut platform,
        );
        let reboot_index = events
            .borrow()
            .iter()
            .position(|event| *event == "reboot")
            .unwrap();
        let readback_index = events
            .borrow()
            .iter()
            .position(|event| *event == "read-next")
            .unwrap();
        assert!(readback_index < reboot_index, "events={events:?}");
        match reply {
            RebootReply::Rejected { .. } => {
                assert!(matches!(result, Err(Error::FlowFailure { .. })))
            }
            RebootReply::Unknown => assert!(result.unwrap().stages.contains(&stage)),
            RebootReply::Accepted => unreachable!(),
        }
    }
}

#[test]
fn windows_default_rollback_is_always_unsafe_and_non_mutating() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut store = Store {
        state: RecordState::Ready(target()),
        saves: 0,
        events: None,
    };
    let firmware = Firmware {
        events: events.clone(),
        firmware_type: FirmwareType::Uefi,
        next: Some(BootId(7)),
        readback: None,
        next_reads: 0,
        writes: 0,
    };
    let reboot = Reboot {
        events,
        reply: RebootReply::Accepted,
    };
    let mut platform = WindowsPlatform::new(&mut store, firmware, reboot);
    assert_eq!(
        platform.rollback_next(Some(BootId(4)), BootId(7)),
        boothop_core::RollbackOutcome::Unsafe
    );
}

#[cfg(windows)]
#[test]
fn production_factory_is_public_without_exposing_injected_boundaries() {
    // Compile-only accessibility proof for a separate dependent crate.  Do
    // not invoke it: construction would touch native protected-store APIs.
    let _factory = boothop_platform::windows::production;
}

#[test]
fn accepted_shutdown_call_with_restore_failure_is_unknown() {
    let mut token = ShutdownToken {
        lookup: Ok(Luid(19)),
        enable: Ok(()),
        prior: TokenPrivileges::single(Luid(19), 0),
        adjustments: Vec::new(),
        closes: 0,
        close_error: Some(5),
    };
    assert_eq!(fake_native_reboot(&mut token, true), RebootReply::Unknown);
}

fn fake_native_reboot(token: &mut ShutdownToken, native_success: bool) -> RebootReply {
    let mut accepted = false;
    let result = with_shutdown_privilege(token, |_| {
        if native_success {
            accepted = true;
            Ok(())
        } else {
            Err(Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Reboot,
                raw_code: 5,
            })
        }
    });
    boothop_platform::windows::classify_reboot_result(accepted, result)
}

#[test]
fn only_definite_zero_native_return_is_rejected() {
    assert_eq!(
        boothop_platform::windows::classify_reboot_result(
            false,
            Err(Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Reboot,
                raw_code: 5,
            }),
        ),
        RebootReply::Rejected { raw_code: 5 }
    );
    assert_eq!(
        boothop_platform::windows::classify_reboot_result(
            false,
            Err(Error::PrivilegeEnableFailed { raw_code: 1300 }),
        ),
        RebootReply::Rejected { raw_code: 1300 }
    );
    assert_eq!(
        boothop_platform::windows::classify_reboot_result(true, Ok(())),
        RebootReply::Accepted
    );
    let mut token = ShutdownToken {
        lookup: Ok(Luid(19)),
        enable: Ok(()),
        prior: TokenPrivileges::single(Luid(19), 0),
        adjustments: Vec::new(),
        closes: 0,
        close_error: None,
    };
    assert_eq!(
        fake_native_reboot(&mut token, false),
        RebootReply::Rejected { raw_code: 5 }
    );
}

#[test]
fn shutdown_privilege_scope_restores_exact_prior_state_and_closes_once() {
    let prior = TokenPrivileges::new(vec![(Luid(17), 0), (Luid(18), 4)]);
    let mut token = ShutdownToken {
        lookup: Ok(Luid(19)),
        enable: Ok(()),
        prior: prior.clone(),
        adjustments: Vec::new(),
        closes: 0,
        close_error: None,
    };
    with_shutdown_privilege(&mut token, |_| Ok::<_, Error>(())).unwrap();
    assert_eq!(token.adjustments.len(), 2);
    assert_eq!(token.adjustments[1], prior);
    assert_eq!(token.closes, 1);
}

#[test]
fn shutdown_privilege_absence_and_not_all_assigned_fail_closed() {
    let mut absent = ShutdownToken {
        lookup: Err(1313),
        enable: Ok(()),
        prior: TokenPrivileges::new(Vec::new()),
        adjustments: Vec::new(),
        closes: 0,
        close_error: None,
    };
    assert_eq!(
        with_shutdown_privilege(&mut absent, |_| Ok::<_, Error>(())),
        Err(Error::PrivilegeUnavailable)
    );
    let mut denied = ShutdownToken {
        lookup: Ok(Luid(19)),
        enable: Err(ERROR_NOT_ALL_ASSIGNED),
        prior: TokenPrivileges::single(Luid(19), 0),
        adjustments: Vec::new(),
        closes: 0,
        close_error: None,
    };
    assert_eq!(
        with_shutdown_privilege(&mut denied, |_| Ok::<_, Error>(())),
        Err(Error::PrivilegeEnableFailed {
            raw_code: ERROR_NOT_ALL_ASSIGNED
        })
    );
    assert_eq!(denied.closes, 1);
}
