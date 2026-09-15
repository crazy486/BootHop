use boothop_core::{
    BootId, Error, OptionInventory, Os, Platform, RebootOutcome, RecordState, Request,
    RollbackOutcome, TargetRecord,
};
use boothop_helper::dispatch::{SessionIo, serve_windows};
use boothop_helper::windows::{
    OPERATION_MUTEX_DACL, OPERATION_MUTEX_NAME, OperationMutex, WaitOutcome, WindowsOperationGuard,
};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Default)]
struct MutexFake(Rc<RefCell<Vec<String>>>);
impl OperationMutex for MutexFake {
    fn create(&mut self, name: &str, dacl: &str) -> Result<(), Error> {
        self.0.borrow_mut().push(format!("create:{name}:{dacl}"));
        Ok(())
    }
    fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
        self.0.borrow_mut().push("wait".into());
        Ok(WaitOutcome::Acquired)
    }
    fn release(&mut self) -> Result<(), Error> {
        self.0.borrow_mut().push("release".into());
        Ok(())
    }
}

struct FakePlatform {
    calls: Rc<RefCell<Vec<&'static str>>>,
    record: RecordState,
    options: OptionInventory,
}
impl Platform for FakePlatform {
    fn load_record(&mut self) -> Result<RecordState, Error> {
        self.calls.borrow_mut().push("load");
        Ok(self.record.clone())
    }
    fn save_record(&mut self, _: &TargetRecord) -> Result<(), Error> {
        Ok(())
    }
    fn read_options(&mut self) -> Result<OptionInventory, Error> {
        self.calls.borrow_mut().push("options");
        Ok(self.options.clone())
    }
    fn read_next(&mut self) -> Result<Option<BootId>, Error> {
        Ok(None)
    }
    fn write_next(&mut self, _: BootId) -> Result<(), Error> {
        Ok(())
    }
    fn rollback_next(&mut self, _: Option<BootId>, _: BootId) -> RollbackOutcome {
        RollbackOutcome::Unsafe
    }
    fn reboot(&mut self) -> RebootOutcome {
        RebootOutcome::Accepted
    }
    fn check_environment(&mut self) -> Result<(), Error> {
        self.calls.borrow_mut().push("environment");
        Ok(())
    }
}

#[test]
fn guard_uses_exact_global_mutex_contract_and_releases_once_after_scope() {
    let events = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let _guard = WindowsOperationGuard::acquire(MutexFake(events.clone())).unwrap();
        assert_eq!(
            events.borrow()[0],
            format!("create:{OPERATION_MUTEX_NAME}:{OPERATION_MUTEX_DACL}")
        );
        assert_eq!(&events.borrow()[1..], ["wait"]);
    }
    assert_eq!(&events.borrow()[2..], ["release"]);
}

#[test]
fn timeout_and_abandonment_fail_closed_before_platform_construction() {
    #[derive(Clone)]
    struct Outcome(WaitOutcome);
    impl OperationMutex for Outcome {
        fn create(&mut self, _: &str, _: &str) -> Result<(), Error> {
            Ok(())
        }
        fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
            Ok(self.0)
        }
        fn release(&mut self) -> Result<(), Error> {
            panic!("not acquired")
        }
    }
    assert!(matches!(
        WindowsOperationGuard::acquire(Outcome(WaitOutcome::Timeout)),
        Err(Error::Busy)
    ));
    assert!(matches!(
        WindowsOperationGuard::acquire(Outcome(WaitOutcome::Abandoned)),
        Err(Error::PlatformIo {
            operation: boothop_core::PlatformOperation::Lock,
            ..
        })
    ));
}

#[test]
fn explicit_finish_propagates_release_failure_and_never_releases_twice() {
    let events = Rc::new(RefCell::new(Vec::<String>::new()));
    struct FailingRelease(Rc<RefCell<Vec<String>>>);
    impl OperationMutex for FailingRelease {
        fn create(&mut self, _: &str, _: &str) -> Result<(), Error> {
            Ok(())
        }
        fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
            Ok(WaitOutcome::Acquired)
        }
        fn release(&mut self) -> Result<(), Error> {
            self.0.borrow_mut().push("release".into());
            Err(Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Lock,
                raw_code: 5,
            })
        }
    }
    let guard = WindowsOperationGuard::acquire(FailingRelease(events.clone())).unwrap();
    assert!(matches!(
        guard.finish(),
        Err(Error::PlatformIo {
            operation: boothop_core::PlatformOperation::Lock,
            raw_code: 5
        })
    ));
    assert_eq!(&events.borrow()[..], ["release"]);
}

#[test]
fn serve_windows_releases_only_after_terminal_send_and_surfaces_release_failure() {
    struct Io {
        input: Vec<u8>,
        events: Rc<RefCell<Vec<String>>>,
    }
    impl SessionIo for Io {
        fn receive(&mut self) -> Result<Vec<u8>, Error> {
            Ok(self.input.clone())
        }
        fn send(&mut self, _: &[u8]) -> Result<(), Error> {
            self.events.borrow_mut().push("send".into());
            Ok(())
        }
    }
    struct OrderedMutex(Rc<RefCell<Vec<String>>>);
    impl OperationMutex for OrderedMutex {
        fn create(&mut self, _: &str, _: &str) -> Result<(), Error> {
            self.0.borrow_mut().push("create".into());
            Ok(())
        }
        fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
            self.0.borrow_mut().push("wait".into());
            Ok(WaitOutcome::Acquired)
        }
        fn release(&mut self) -> Result<(), Error> {
            self.0.borrow_mut().push("release".into());
            Err(Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Lock,
                raw_code: 6,
            })
        }
    }
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut io = Io {
        input: boothop_protocol::encode_request(Request::Inspect).unwrap(),
        events: events.clone(),
    };
    let result = serve_windows(
        &mut io,
        || Ok(()),
        || WindowsOperationGuard::acquire(OrderedMutex(events.clone())),
        |_| {
            Ok(FakePlatform {
                calls: Rc::new(RefCell::new(Vec::new())),
                record: RecordState::Missing,
                options: OptionInventory {
                    entries: vec![],
                    diagnostics: vec![],
                },
            })
        },
    );
    assert!(matches!(
        result,
        Err(Error::PlatformIo {
            operation: boothop_core::PlatformOperation::Lock,
            raw_code: 6
        })
    ));
    assert_eq!(
        &events.borrow()[..],
        ["send", "create", "wait", "send", "release"]
    );
}

#[test]
fn send_error_still_releases_once_after_terminal_attempt() {
    struct FailingIo {
        input: Vec<u8>,
        sends: usize,
        events: Rc<RefCell<Vec<String>>>,
    }
    impl SessionIo for FailingIo {
        fn receive(&mut self) -> Result<Vec<u8>, Error> {
            Ok(self.input.clone())
        }
        fn send(&mut self, _: &[u8]) -> Result<(), Error> {
            self.sends += 1;
            self.events.borrow_mut().push(format!("send{}", self.sends));
            if self.sends == 2 {
                Err(Error::PlatformIo {
                    operation: boothop_core::PlatformOperation::Ipc,
                    raw_code: 7,
                })
            } else {
                Ok(())
            }
        }
    }
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut io = FailingIo {
        input: boothop_protocol::encode_request(Request::Inspect).unwrap(),
        sends: 0,
        events: events.clone(),
    };
    let result = serve_windows(
        &mut io,
        || Ok(()),
        || WindowsOperationGuard::acquire(OrderedMutexForTest(events.clone())),
        |_| {
            Ok(FakePlatform {
                calls: Rc::new(RefCell::new(Vec::new())),
                record: RecordState::Missing,
                options: OptionInventory {
                    entries: vec![],
                    diagnostics: vec![],
                },
            })
        },
    );
    assert!(matches!(
        result,
        Err(Error::PlatformIo {
            operation: boothop_core::PlatformOperation::Ipc,
            raw_code: 7
        })
    ));
    assert!(events.borrow().iter().any(|event| event == "release"));
}

#[test]
fn unwind_attempts_one_release_without_running_platform_cleanup() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = WindowsOperationGuard::acquire(OrderedMutexForTest(events.clone())).unwrap();
        panic!("synthetic terminal unwind");
    }));
    assert!(result.is_err());
    assert_eq!(
        events
            .borrow()
            .iter()
            .filter(|event| *event == "release")
            .count(),
        1
    );
}

struct OrderedMutexForTest(Rc<RefCell<Vec<String>>>);
impl OperationMutex for OrderedMutexForTest {
    fn create(&mut self, _: &str, _: &str) -> Result<(), Error> {
        self.0.borrow_mut().push("create".into());
        Ok(())
    }
    fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
        self.0.borrow_mut().push("wait".into());
        Ok(WaitOutcome::Acquired)
    }
    fn release(&mut self) -> Result<(), Error> {
        self.0.borrow_mut().push("release".into());
        Ok(())
    }
}

#[test]
fn run_windows_fixes_host_os_and_dispatches_one_terminal_result() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let option = fixture_option();
    let identity = boothop_core::canonicalize(&option).unwrap();
    let platform = FakePlatform {
        calls,
        record: RecordState::Ready(TargetRecord {
            boot_id: BootId(7),
            os: Os::Windows,
            identity,
        }),
        options: OptionInventory {
            entries: vec![(BootId(7), option)],
            diagnostics: vec![],
        },
    };
    let id = boothop_protocol::RequestId::parse("0123456789abcdef0123456789abcde1").unwrap();
    let input = boothop_protocol::encode_request_with_id(
        &id,
        Request::Configure {
            boot_id: BootId(1),
            os: Os::Windows,
        },
    )
    .unwrap();
    let mut io = CaptureIo {
        input,
        output: vec![],
    };
    serve_windows(
        &mut io,
        || Ok(()),
        || WindowsOperationGuard::acquire(MutexFake::default()),
        |_| Ok(platform),
    )
    .unwrap();
    assert_eq!(
        boothop_protocol::decode_response(&io.output[1]),
        Ok(Err(Error::UnexpectedOs))
    );
}

struct CaptureIo {
    input: Vec<u8>,
    output: Vec<Vec<u8>>,
}
impl SessionIo for CaptureIo {
    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.input.clone())
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.output.push(bytes.to_vec());
        Ok(())
    }
}

fn fixture_option() -> boothop_core::LoadOption {
    let hex = include_str!("../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
    let bytes: Vec<_> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    boothop_core::parse_load_option(&bytes).unwrap()
}

#[test]
fn authentication_precedes_guard_and_native_platform_construction() {
    let events = Rc::new(RefCell::new(Vec::<String>::new()));
    let mut io = CaptureIo {
        input: boothop_protocol::encode_request(Request::Inspect).unwrap(),
        output: vec![],
    };
    let result = serve_windows(
        &mut io,
        || {
            Err(Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Ipc,
                raw_code: 1,
            })
        },
        || {
            events.borrow_mut().push("guard".into());
            WindowsOperationGuard::acquire(MutexFake(events.clone()))
        },
        |_| -> Result<FakePlatform, Error> { panic!("construct must not run") },
    );
    assert!(result.is_err());
    assert!(events.borrow().is_empty());
    assert!(io.output.is_empty());
}
