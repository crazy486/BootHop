use boothop_core::{
    BootId, Error, OptionInventory, Os, Platform, RebootOutcome, RecordState, Request,
    RollbackOutcome, TargetRecord,
};
use boothop_helper::dispatch::SendResult;
use boothop_helper::windows::{
    OPERATION_MUTEX_DACL, OPERATION_MUTEX_NAME, OperationMutex, WaitOutcome, WindowsOperationGuard,
    dispatch_authenticated, run_windows,
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
}
impl Platform for FakePlatform {
    fn load_record(&mut self) -> Result<RecordState, Error> {
        self.calls.borrow_mut().push("load");
        Ok(RecordState::Missing)
    }
    fn save_record(&mut self, _: &TargetRecord) -> Result<(), Error> {
        Ok(())
    }
    fn read_options(&mut self) -> Result<OptionInventory, Error> {
        self.calls.borrow_mut().push("options");
        Ok(OptionInventory {
            entries: vec![],
            diagnostics: vec![],
        })
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
fn run_windows_fixes_host_os_and_dispatches_one_terminal_result() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut platform = FakePlatform { calls };
    let mut responses = Vec::new();
    let send: &mut SendResult<'_> = &mut |result| {
        responses.push(result);
        Ok(())
    };
    run_windows(
        Request::Configure {
            boot_id: BootId(1),
            os: Os::Linux,
        },
        &mut platform,
        send,
    )
    .unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0], Err(Error::UnexpectedOs));
}

#[test]
fn authentication_precedes_guard_and_native_platform_construction() {
    let events = Rc::new(RefCell::new(Vec::<String>::new()));
    let mut send: &mut SendResult<'_> = &mut |_| Ok(());
    let result = dispatch_authenticated::<MutexFake, FakePlatform>(
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
        Request::Inspect,
        |_| {
            events.borrow_mut().push("construct".into());
            Ok(FakePlatform {
                calls: Rc::new(RefCell::new(Vec::new())),
            })
        },
        &mut send,
    );
    assert!(result.is_err());
    assert!(events.borrow().is_empty());
}
