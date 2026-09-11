use boothop_core::{
    BootId, EnumerationDiagnostic, OptionInventory, Os, Platform, RebootOutcome, RecordState,
    Stage, TargetRecord,
};
use boothop_core::{Error, Request};
use boothop_helper::dispatch::{SessionIo, serve};
use boothop_helper::protocol::{decode_hello, encode_request};
use boothop_helper::{dispatch::run_linux, lock::with_operation, protocol::decode_response};
use boothop_platform::ProtectedStore;
use std::{cell::RefCell, rc::Rc};
#[path = "../../platform/tests/support/mod.rs"]
mod support;

#[derive(Default)]
struct State {
    writes: Vec<BootId>,
    reboots: usize,
    reads: usize,
    next: Option<BootId>,
    bytes: Vec<u8>,
}
struct Flow<'a> {
    store: &'a mut dyn ProtectedStore,
    fs: support::FakeFs,
    state: Rc<RefCell<State>>,
}
impl Platform for Flow<'_> {
    fn load_record(&mut self) -> Result<RecordState, Error> {
        assert!(self.fs.held());
        self.store.load()
    }
    fn save_record(&mut self, t: &TargetRecord) -> Result<(), Error> {
        assert!(self.fs.held());
        self.store.save(t)
    }
    fn read_options(&mut self) -> Result<OptionInventory, Error> {
        assert!(self.fs.held());
        let mut s = self.state.borrow_mut();
        s.reads += 1;
        let option = boothop_core::parse_load_option(&s.bytes)?;
        Ok(OptionInventory {
            entries: vec![(BootId(7), option.clone()), (BootId(8), option)],
            diagnostics: vec![EnumerationDiagnostic::DuplicateBootOrder(BootId(7))],
        })
    }
    fn check_environment(&mut self) -> Result<(), Error> {
        assert!(self.fs.held());
        Ok(())
    }
    fn read_next(&mut self) -> Result<Option<BootId>, Error> {
        assert!(self.fs.held());
        Ok(self.state.borrow().next)
    }
    fn write_next(&mut self, id: BootId) -> Result<(), Error> {
        assert!(self.fs.held());
        let mut s = self.state.borrow_mut();
        s.writes.push(id);
        s.next = Some(id);
        Ok(())
    }
    fn reboot(&mut self) -> RebootOutcome {
        assert!(self.fs.held());
        self.state.borrow_mut().reboots += 1;
        RebootOutcome::Accepted
    }
}
fn state() -> Rc<RefCell<State>> {
    let hex = include_str!("../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
    let bytes = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    Rc::new(RefCell::new(State {
        bytes,
        ..State::default()
    }))
}
fn flow(
    fs: support::FakeFs,
    state: Rc<RefCell<State>>,
    request: Request,
) -> Result<boothop_core::Report, Error> {
    let mut io = Io {
        input: encode_request(request).unwrap(),
        ..Io::default()
    };
    serve(0, &mut io, |request, send| {
        with_operation(fs.clone(), |store| {
            let mut platform = Flow {
                store,
                fs: fs.clone(),
                state,
            };
            run_linux(request, &mut platform, &mut |result| {
                assert!(fs.held());
                assert!(matches!(
                    boothop_platform::linux::store::LockedStore::acquire(fs.clone()),
                    Err(Error::Busy)
                ));
                send(result)?;
                assert!(fs.held()); // send completed while the operation guard still exists.
                Ok(())
            })
        })
    })
    .unwrap();
    assert!(!fs.held());
    assert_eq!(io.output.len(), 2);
    decode_response(&io.output[1]).unwrap()
}

#[test]
fn configure_uses_current_buffer_under_lock_and_reports_diagnostics() {
    let fs = support::FakeFs::installed();
    let state = state();
    let inspected = flow(fs.clone(), state.clone(), Request::Inspect).unwrap();
    assert_eq!(inspected.record, boothop_core::RecordDiagnostic::Missing);
    assert!(inspected.stages.is_empty());
    state.borrow_mut().bytes.extend([0xde, 0xad, 0xbe, 0xef]);
    let report = flow(
        fs.clone(),
        state.clone(),
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows,
        },
    )
    .unwrap();
    let saved = boothop_core::decode_record(&fs.record().unwrap()).unwrap();
    assert_eq!(
        saved.identity,
        boothop_core::canonicalize(
            &boothop_core::parse_load_option(&state.borrow().bytes).unwrap()
        )
        .unwrap()
    );
    assert_eq!(saved.boot_id, BootId(7));
    assert_eq!(report.stages, [Stage::TargetValidated]);
    assert_eq!(
        report.diagnostics,
        [EnumerationDiagnostic::DuplicateBootOrder(BootId(7))]
    );
    assert!(state.borrow().writes.is_empty());
    assert_eq!(state.borrow().reboots, 0);
}
#[test]
fn switch_selects_protected_record_even_when_another_id_has_equal_identity() {
    let fs = support::FakeFs::installed();
    let state = state();
    flow(
        fs.clone(),
        state.clone(),
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows,
        },
    )
    .unwrap();
    assert_eq!(
        boothop_core::decode_record(&fs.record().unwrap()),
        Ok(support::target())
    );
    let report = flow(fs, state.clone(), Request::Switch { os: Os::Windows }).unwrap();
    assert_eq!(state.borrow().writes, [BootId(7)]);
    assert_eq!(state.borrow().reboots, 1);
    assert_eq!(
        report.stages,
        [
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootAccepted
        ]
    );
}
#[test]
fn missing_or_changed_identity_cannot_write() {
    let fs = support::FakeFs::installed();
    let state = state();
    assert_eq!(
        flow(
            fs.clone(),
            state.clone(),
            Request::Switch { os: Os::Windows }
        ),
        Err(Error::NotConfigured)
    );
    flow(
        fs.clone(),
        state.clone(),
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows,
        },
    )
    .unwrap();
    state.borrow_mut().bytes.push(1);
    assert_eq!(
        flow(fs, state.clone(), Request::Switch { os: Os::Windows }),
        Err(Error::IdentityMismatch)
    );
    assert!(state.borrow().writes.is_empty());
    assert_eq!(state.borrow().reboots, 0);
}
#[test]
fn unknown_record_is_not_overwritten_or_enumerated() {
    let fs = support::FakeFs::installed();
    fs.set_record(br#"{"version":999}"#.to_vec());
    let old = fs.record();
    let state = state();
    for request in [
        Request::Inspect,
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows,
        },
        Request::Switch { os: Os::Windows },
    ] {
        assert_eq!(
            flow(fs.clone(), state.clone(), request),
            Err(Error::UnsupportedRecordVersion { found: 999 })
        );
        assert_eq!(fs.record(), old);
        assert_eq!(state.borrow().reads, 0);
        assert!(state.borrow().writes.is_empty());
    }
}
#[test]
fn fixed_linux_host_rejects_linux_target() {
    let fs = support::FakeFs::installed();
    let state = state();
    for request in [
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Linux,
        },
        Request::Switch { os: Os::Linux },
    ] {
        assert_eq!(
            flow(fs.clone(), state.clone(), request),
            Err(Error::UnexpectedOs)
        );
    }
    assert_eq!(state.borrow().reads, 0);
    assert_eq!(fs.record(), None);
}
#[test]
fn lock_acquisition_failure_is_one_domain_response() {
    let fs = support::FakeFs::installed();
    let guard = boothop_platform::linux::store::LockedStore::acquire(fs.clone()).unwrap();
    let mut io = Io {
        input: encode_request(Request::Inspect).unwrap(),
        ..Io::default()
    };
    serve(0, &mut io, |_, _| {
        with_operation(fs, |_| panic!("busy cannot execute"))
    })
    .unwrap();
    assert_eq!(io.output.len(), 2);
    assert_eq!(decode_response(&io.output[1]), Ok(Err(Error::Busy)));
    drop(guard);
}
#[test]
fn no_retry_on_send_failure_and_no_second_response() {
    let mut io = Io {
        input: encode_request(Request::Inspect).unwrap(),
        ..Io::default()
    };
    assert_eq!(
        serve(0, &mut io, |_, send| {
            send(Err(Error::Busy))?;
            send(Err(Error::NotConfigured))
        }),
        Err(Error::UnsupportedFormat)
    );
    assert_eq!(io.output.len(), 2);
    struct BrokenOutput {
        attempts: usize,
    }
    impl SessionIo for BrokenOutput {
        fn receive(&mut self) -> Result<Vec<u8>, Error> {
            Ok(encode_request(Request::Inspect).unwrap())
        }
        fn send(&mut self, _: &[u8]) -> Result<(), Error> {
            self.attempts += 1;
            if self.attempts == 1 {
                Ok(())
            } else {
                Err(Error::ResourceLimit)
            }
        }
    }
    let mut broken = BrokenOutput { attempts: 0 };
    assert_eq!(
        serve(0, &mut broken, |_, send| send(Err(Error::Busy))),
        Err(Error::ResourceLimit)
    );
    assert_eq!(broken.attempts, 2);
}
#[derive(Default)]
struct Io {
    input: Vec<u8>,
    output: Vec<Vec<u8>>,
}
impl SessionIo for Io {
    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.input.clone())
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.output.push(bytes.to_vec());
        Ok(())
    }
}
#[test]
fn non_root_cannot_hello_or_dispatch() {
    let mut io = Io::default();
    assert!(serve(1000, &mut io, |_, _| panic!("untrusted dispatch")).is_err());
    assert!(io.output.is_empty());
}
#[test]
fn root_sends_hello_then_accepts_only_one_request() {
    let mut io = Io {
        input: encode_request(Request::Inspect).unwrap().repeat(2),
        ..Io::default()
    };
    assert!(
        serve(0, &mut io, |_, _| panic!(
            "second request must reject whole input"
        ))
        .is_err()
    );
    assert_eq!(io.output.len(), 1);
    assert_eq!(decode_hello(&io.output[0]), Ok(()));
}
