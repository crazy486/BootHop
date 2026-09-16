use boothop_core::{Error, PlatformOperation};
use boothop_helper::windows::pipe::{
    AuthEvidence, DEFAULT_AUTH_DEADLINE, DEFAULT_OPERATION_DEADLINE, HelperArgs, ImageEvidence,
    OverlappedEvent, PeerVerifier, PipePolicy, SelfEvidence, TokenEvidence, TokenLabelLayout,
    Watchdog, WatchdogDecision, WatchdogState, authenticate_peer, authenticate_peer_on_connection,
    build_pipe_name, parse_args, pipe_dacl_for_user_sid, validate_overlapped_trace,
    validate_pipe_policy, validate_sid_bytes, validate_sid_header, validate_token_label_layout,
    watchdog_decision, watchdog_disarm_state, watchdog_worker_state,
};
use boothop_helper::windows::{
    GUI_IMAGE_PATH, HELPER_IMAGE_PATH, PIPE_DACL, PIPE_MAX_BYTES, PIPE_NAME_PREFIX,
};

fn valid_id() -> &'static str {
    "0123456789abcdef0123456789abcde1"
}

#[test]
fn parser_accepts_only_version_request_id_and_gui_pid_in_order() {
    let args = parse_args(&[
        "--version=2".into(),
        format!("--request-id={}", valid_id()),
        "--gui-pid=42".into(),
    ])
    .unwrap();
    assert_eq!(args, HelperArgs::new(valid_id(), 42).unwrap());
    assert_eq!(
        build_pipe_name(&args.request_id),
        format!("{}{}", PIPE_NAME_PREFIX, valid_id())
    );
}

#[test]
fn parser_rejects_traversal_extra_duplicate_malformed_overlong_relative_and_commands() {
    let cases = [
        vec!["--version=2", "--request-id=../etc", "--gui-pid=42"],
        vec![
            "--version=2",
            "--request-id=0123456789abcdef0123456789abcde1",
            "--gui-pid=42",
            "--extra=x",
        ],
        vec![
            "--version=2",
            "--request-id=0123456789abcdef0123456789abcde1",
            "--gui-pid=42",
            "--gui-pid=43",
        ],
        vec![
            "--version=1",
            "--request-id=0123456789abcdef0123456789abcde1",
            "--gui-pid=42",
        ],
        vec![
            "--version=2",
            "--request-id=0123456789ABCDEF0123456789ABCDE1",
            "--gui-pid=42",
        ],
        vec![
            "--version=2",
            "--request-id=0123456789abcdef0123456789abcde1",
            "--gui-pid=+42",
        ],
        vec![
            "--version=2",
            "--request-id=0123456789abcdef0123456789abcde1",
            "--gui-pid=042",
        ],
        vec![
            "--version=2",
            "--request-id=0123456789abcdef0123456789abcde1",
            "--gui-pid=42",
            "relative.exe",
        ],
        vec![
            "--version=2",
            "--request-id=0123456789abcdef0123456789abcde1",
            "--gui-pid=42",
            "cmd.exe /c whoami",
        ],
    ];
    for values in cases {
        assert!(parse_args(&values.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
    }
    assert!(parse_args(&[]).is_err());
}

#[test]
fn parser_rejects_zero_id_and_zero_or_overflow_pid() {
    for id in [
        "00000000000000000000000000000000",
        "0123456789abcdef0123456789abcde",
    ] {
        assert!(HelperArgs::new(id, 42).is_err());
    }
    for value in ["0", "4294967296"] {
        let args = vec![
            "--version=2".to_owned(),
            format!("--request-id={}", valid_id()),
            format!("--gui-pid={value}"),
        ];
        assert!(parse_args(&args).is_err());
    }
}

#[cfg(windows)]
#[test]
fn parser_os_rejects_invalid_unicode_without_panicking() {
    use boothop_helper::windows::pipe::parse_args_os;
    use std::os::windows::ffi::OsStringExt;
    let invalid = std::ffi::OsString::from_wide(&[0xD800]);
    assert!(parse_args_os(&[invalid]).is_err());
}

#[test]
fn pipe_policy_requires_first_local_instance_and_explicit_minimal_acl() {
    assert!(
        validate_pipe_policy(PipePolicy {
            first_instance: true,
            reject_remote: true,
            dacl: PIPE_DACL,
        })
        .is_ok()
    );
    for policy in [
        PipePolicy {
            first_instance: false,
            ..PipePolicy::secure()
        },
        PipePolicy {
            reject_remote: false,
            ..PipePolicy::secure()
        },
        PipePolicy {
            dacl: "",
            ..PipePolicy::secure()
        },
    ] {
        assert!(validate_pipe_policy(policy).is_err());
    }
}

#[test]
fn pipe_acl_binds_only_the_launching_user_sid_plus_system_and_admins() {
    let acl = pipe_dacl_for_user_sid("S-1-5-21-123-456-789-1001").unwrap();
    assert_eq!(
        acl,
        "D:P(A;;GRGW;;;S-1-5-21-123-456-789-1001)(A;;GRGW;;;SY)(A;;GRGW;;;BA)"
    );
    for sid in ["", "S-1-", "S-1-5-x", "S-1-5-21;evil"] {
        assert!(pipe_dacl_for_user_sid(sid).is_err());
    }
}

fn image(path: &str, reparse: bool) -> ImageEvidence {
    ImageEvidence {
        canonical_path: path.into(),
        reparse,
        file_id: 7,
    }
}

fn token(elevated: bool, high: bool) -> TokenEvidence {
    TokenEvidence {
        elevated,
        high_integrity: high,
        user_sid: "S-1-5-21-1001".into(),
        token_id: 1,
    }
}

#[derive(Default)]
struct FakeVerifier {
    self_evidence: Option<SelfEvidence>,
    peer: Option<AuthEvidence>,
    continuity_evidence: Option<AuthEvidence>,
    continuity_deadlines: Option<std::rc::Rc<std::cell::RefCell<Vec<std::time::Instant>>>>,
    calls: Vec<&'static str>,
}

impl PeerVerifier for FakeVerifier {
    fn inspect_self(&mut self) -> Result<SelfEvidence, Error> {
        self.calls.push("self");
        self.self_evidence.clone().ok_or(Error::UnsupportedFormat)
    }
    fn inspect_peer(&mut self, _pid: u32) -> Result<AuthEvidence, Error> {
        self.calls.push("peer");
        self.peer.clone().ok_or(Error::UnsupportedFormat)
    }
    fn verify_peer_continuity(&mut self, _pid: u32, _evidence: &AuthEvidence) -> Result<(), Error> {
        self.calls.push("continuity");
        if self
            .continuity_evidence
            .as_ref()
            .is_some_and(|expected| expected != _evidence)
        {
            return Err(Error::UnsupportedFormat);
        }
        Ok(())
    }
    fn verify_peer_continuity_until(
        &mut self,
        pid: u32,
        evidence: &AuthEvidence,
        deadline: std::time::Instant,
    ) -> Result<(), Error> {
        if let Some(deadlines) = &self.continuity_deadlines {
            deadlines.borrow_mut().push(deadline);
        }
        self.verify_peer_continuity(pid, evidence)
    }
}

#[test]
fn authentication_requires_elevated_high_integrity_fixed_images_session_and_continuity() {
    let args = HelperArgs::new(valid_id(), 42).unwrap();
    let mut fake = FakeVerifier {
        self_evidence: Some(SelfEvidence {
            token: token(true, true),
            image: image(HELPER_IMAGE_PATH, false),
            session_id: 9,
        }),
        peer: Some(AuthEvidence {
            pid: 42,
            token: token(false, false),
            image: image(GUI_IMAGE_PATH, false),
            session_id: 8,
        }),
        ..FakeVerifier::default()
    };
    assert!(authenticate_peer(&mut fake, &args).is_err());
    assert_eq!(fake.calls, ["self", "peer"]);

    assert!(authenticate_peer(&mut fake, &args).is_err());
    fake.peer.as_mut().unwrap().session_id = 9;
    fake.peer.as_mut().unwrap().image.reparse = true;
    assert!(authenticate_peer(&mut fake, &args).is_err());
    fake.peer.as_mut().unwrap().image.reparse = false;
    assert!(authenticate_peer(&mut fake, &args).is_ok());
    assert_eq!(
        fake.calls,
        [
            "self",
            "peer",
            "self",
            "peer",
            "self",
            "peer",
            "self",
            "peer",
            "continuity"
        ]
    );
}

#[test]
fn continuity_lease_rejects_pid_reuse_image_token_or_session_change() {
    let args = HelperArgs::new(valid_id(), 42).unwrap();
    let original = AuthEvidence {
        pid: 42,
        token: token(false, false),
        image: image(GUI_IMAGE_PATH, false),
        session_id: 9,
    };
    let mut fake = FakeVerifier {
        self_evidence: Some(SelfEvidence {
            token: token(true, true),
            image: image(HELPER_IMAGE_PATH, false),
            session_id: 9,
        }),
        peer: Some(original.clone()),
        continuity_evidence: Some(original),
        ..FakeVerifier::default()
    };
    assert!(authenticate_peer(&mut fake, &args).is_ok());
    let mutations: [fn(&mut AuthEvidence); 4] = [
        |peer: &mut AuthEvidence| peer.pid = 43,
        |peer: &mut AuthEvidence| peer.image.file_id = 8,
        |peer: &mut AuthEvidence| peer.token.token_id = 2,
        |peer: &mut AuthEvidence| peer.session_id = 10,
    ];
    for mutate in mutations {
        let mut changed = fake.peer.clone().unwrap();
        mutate(&mut changed);
        fake.peer = Some(changed);
        assert!(authenticate_peer(&mut fake, &args).is_err());
        fake.peer = fake.continuity_evidence.clone();
    }
}

#[test]
fn authentication_failure_is_generic_and_never_reads_request_bytes() {
    let args = HelperArgs::new(valid_id(), 42).unwrap();
    let mut fake = FakeVerifier {
        self_evidence: Some(SelfEvidence {
            token: token(false, true),
            image: image(HELPER_IMAGE_PATH, false),
            session_id: 9,
        }),
        ..FakeVerifier::default()
    };
    let error = authenticate_peer(&mut fake, &args).unwrap_err();
    assert!(matches!(
        error,
        Error::PlatformIo {
            operation: PlatformOperation::Security,
            ..
        }
    ));
    assert_eq!(fake.calls, ["self"]);
}

#[test]
fn connected_server_pid_must_equal_gui_pid_before_peer_inspection() {
    let args = HelperArgs::new(valid_id(), 42).unwrap();
    let mut fake = FakeVerifier::default();
    assert!(authenticate_peer_on_connection(&mut fake, &args, 43).is_err());
    assert!(fake.calls.is_empty());
}

#[test]
fn frame_length_must_be_exact_and_one_frame_only() {
    use boothop_helper::windows::pipe::validate_frame;
    assert!(validate_frame(&[1, 0, 0, 0, b'x']).is_ok());
    assert!(validate_frame(&[1, 0, 0, 0, b'x', b'y']).is_err());
    assert!(validate_frame(&[0xff, 0xff, 0, 0]).is_err());
}

#[test]
fn helper_source_has_no_persistent_or_command_execution_capability() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut source = String::new();
    for entry in walkdir(&root) {
        source.push_str(&std::fs::read_to_string(entry).unwrap());
    }
    for forbidden in [
        "CreateService",
        "OpenSCManager",
        "RunOnce",
        "CreateProcess",
        "ShellExecute",
        "LoadLibrary",
        "GetProcAddress",
        "bcdedit",
        "InitiateSystemShutdown",
        "ExitWindows",
        "SetFirmwareEnvironmentVariable",
        "GetFirmwareEnvironmentVariable",
        "AdjustTokenPrivileges",
        "WriteProcessMemory",
        "SetFileInformationByHandle",
        "RegCreateKey",
        "RegSetValue",
        "MoveFile",
        "DeleteFile",
        "DeviceIoControl",
        "NtSetSystemInformation",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden helper capability: {forbidden}"
        );
    }
}

#[test]
fn mutex_resource_model_closes_native_handle_on_create_and_wait_failures() {
    use boothop_helper::windows::{OperationMutex, WaitOutcome, WindowsOperationGuard};
    use std::cell::Cell;
    use std::rc::Rc;

    struct HandleModel {
        closed: Rc<Cell<bool>>,
        create_ok: bool,
        wait: WaitOutcome,
        opened: bool,
    }
    impl OperationMutex for HandleModel {
        fn create(&mut self, _: &str, _: &str) -> Result<(), Error> {
            if !self.create_ok {
                // Model a native handle allocated before a post-create
                // validation error; Drop must still close it.
                self.opened = true;
                return Err(Error::PlatformIo {
                    operation: PlatformOperation::Lock,
                    raw_code: 5,
                });
            }
            self.opened = true;
            Ok(())
        }
        fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
            Ok(self.wait)
        }
        fn release(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }
    impl Drop for HandleModel {
        fn drop(&mut self) {
            if self.opened {
                self.closed.set(true);
            }
        }
    }

    let create_closed = Rc::new(Cell::new(false));
    assert!(
        WindowsOperationGuard::acquire(HandleModel {
            closed: create_closed.clone(),
            create_ok: false,
            wait: WaitOutcome::Acquired,
            opened: false,
        })
        .is_err()
    );
    assert!(create_closed.get());

    let wait_closed = Rc::new(Cell::new(false));
    assert!(
        WindowsOperationGuard::acquire(HandleModel {
            closed: wait_closed.clone(),
            create_ok: true,
            wait: WaitOutcome::Timeout,
            opened: false,
        })
        .is_err()
    );
    assert!(wait_closed.get());
}

#[test]
fn authenticated_session_authenticates_before_receive_and_closes_once() {
    use boothop_helper::windows::pipe::{PipeIo, serve_authenticated_session};
    use boothop_helper::windows::{OperationMutex, WaitOutcome};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Io {
        events: Rc<RefCell<Vec<&'static str>>>,
        deadlines: Rc<RefCell<Vec<std::time::Instant>>>,
    }
    impl PipeIo for Io {
        fn receive_frame(&mut self, deadline: std::time::Instant) -> Result<Vec<u8>, Error> {
            self.events.borrow_mut().push("receive");
            self.deadlines.borrow_mut().push(deadline);
            Ok(boothop_helper::protocol::encode_request_with_id(
                &boothop_protocol::RequestId::parse(valid_id()).unwrap(),
                boothop_core::Request::Inspect,
            )
            .unwrap())
        }
        fn send_frame(&mut self, _: &[u8], deadline: std::time::Instant) -> Result<(), Error> {
            self.events.borrow_mut().push("send");
            self.deadlines.borrow_mut().push(deadline);
            Ok(())
        }
        fn close(&mut self) -> Result<(), Error> {
            self.events.borrow_mut().push("close");
            Ok(())
        }
    }
    #[derive(Clone)]
    struct NoopMutex;
    impl OperationMutex for NoopMutex {
        fn create(&mut self, _: &str, _: &str) -> Result<(), Error> {
            Ok(())
        }
        fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
            Ok(WaitOutcome::Acquired)
        }
        fn release(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }
    let events = Rc::new(RefCell::new(Vec::new()));
    let deadlines = Rc::new(RefCell::new(Vec::new()));
    let continuity_deadlines = Rc::new(RefCell::new(Vec::new()));
    let mut io = Io {
        events: events.clone(),
        deadlines: deadlines.clone(),
    };
    let args = HelperArgs::new(valid_id(), 42).unwrap();
    let mut verifier = FakeVerifier {
        self_evidence: Some(SelfEvidence {
            token: token(true, true),
            image: image(HELPER_IMAGE_PATH, false),
            session_id: 9,
        }),
        peer: Some(AuthEvidence {
            pid: 42,
            token: token(false, false),
            image: image(GUI_IMAGE_PATH, false),
            session_id: 9,
        }),
        continuity_deadlines: Some(continuity_deadlines.clone()),
        ..FakeVerifier::default()
    };
    let result = serve_authenticated_session::<
        _,
        _,
        NoopMutex,
        boothop_platform::windows::WindowsPlatform<FakeStore, FakeFirmware, FakeReboot>,
    >(
        &mut io,
        &args,
        &mut verifier,
        || Err(Error::Busy),
        |_| unreachable!("construction is not reached after lock failure"),
    );
    assert_eq!(result, Ok(()));
    assert_eq!(&events.borrow()[..], ["send", "receive", "send", "close"]);
    assert_eq!(deadlines.borrow().len(), 3);
    assert!(deadlines.borrow().windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(continuity_deadlines.borrow().len(), 3);
    assert_eq!(
        continuity_deadlines.borrow()[1],
        continuity_deadlines.borrow()[2]
    );
}

struct FakeStore;
struct FakeFirmware;
struct FakeReboot;
impl boothop_platform::ProtectedStore for FakeStore {
    fn load(&mut self) -> Result<boothop_core::RecordState, Error> {
        Ok(boothop_core::RecordState::Missing)
    }
    fn save(&mut self, _: &boothop_core::TargetRecord) -> Result<(), Error> {
        Ok(())
    }
}
impl boothop_platform::windows::WindowsCalls for FakeFirmware {
    fn firmware_type(
        &mut self,
    ) -> Result<boothop_platform::windows::FirmwareType, boothop_platform::windows::CallError> {
        unreachable!()
    }
    fn read_variable(
        &mut self,
        _: boothop_platform::windows::VariableName,
        _: usize,
    ) -> boothop_platform::windows::ReadOutcome {
        unreachable!()
    }
    fn write_boot_next(&mut self, _: [u8; 2]) -> Result<(), boothop_platform::windows::CallError> {
        unreachable!()
    }
}
impl boothop_platform::windows::RebootCalls for FakeReboot {
    fn request_reboot(&mut self) -> boothop_platform::windows::RebootReply {
        unreachable!()
    }
}

fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walkdir(&path));
        } else if path.extension().and_then(|v| v.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    files
}

#[test]
fn protocol_limits_and_deadlines_are_fixed_and_command_line_has_no_secret() {
    assert_eq!(PIPE_MAX_BYTES, 65_536);
    assert_eq!(DEFAULT_AUTH_DEADLINE, std::time::Duration::from_secs(120));
    assert_eq!(
        DEFAULT_OPERATION_DEADLINE,
        std::time::Duration::from_secs(30)
    );
    let args = format!("--version=2 --request-id={} --gui-pid=42", valid_id());
    assert!(!args.contains("secret"));
    assert!(!args.contains("token"));
}

#[test]
fn token_label_layout_requires_aligned_bounded_complete_storage() {
    let valid = TokenLabelLayout {
        label_offset: 0,
        sid_offset: 16,
        sid_length: 16,
        subauthority_count: 2,
    };
    assert!(validate_token_label_layout(1024, 32, valid).is_ok());
    for invalid in [
        TokenLabelLayout {
            label_offset: 1,
            ..valid
        },
        TokenLabelLayout {
            sid_offset: 31,
            ..valid
        },
        TokenLabelLayout {
            sid_length: 0,
            ..valid
        },
        TokenLabelLayout {
            subauthority_count: 0,
            ..valid
        },
    ] {
        assert!(validate_token_label_layout(1024, 32, invalid).is_err());
    }
    assert!(validate_token_label_layout(1024, 8, valid).is_err());
    assert!(validate_token_label_layout(24, 32, valid).is_err());
    assert!(
        validate_token_label_layout(
            1024,
            32,
            TokenLabelLayout {
                sid_offset: usize::MAX,
                ..valid
            }
        )
        .is_err()
    );
    assert!(
        validate_token_label_layout(
            1024,
            1024,
            TokenLabelLayout {
                subauthority_count: u8::MAX,
                sid_length: 1024,
                ..valid
            }
        )
        .is_err()
    );
}

#[test]
fn token_label_layout_rejects_null_and_malformed_sid_bounds() {
    let valid = TokenLabelLayout {
        label_offset: 0,
        sid_offset: 16,
        sid_length: 16,
        subauthority_count: 2,
    };
    assert!(
        validate_token_label_layout(
            1024,
            32,
            TokenLabelLayout {
                sid_offset: usize::MAX,
                ..valid
            }
        )
        .is_err()
    );
    assert!(
        validate_token_label_layout(
            1024,
            32,
            TokenLabelLayout {
                sid_length: 8,
                ..valid
            }
        )
        .is_err()
    );
    assert!(
        validate_token_label_layout(
            1024,
            32,
            TokenLabelLayout {
                subauthority_count: 4,
                ..valid
            }
        )
        .is_err()
    );
    let mut sid = vec![0u8; 16];
    sid[0] = 1;
    sid[1] = 2;
    assert!(validate_sid_bytes(&sid, 2).is_ok());
    sid[0] = 2;
    assert!(validate_sid_bytes(&sid, 2).is_err());
    assert!(validate_sid_bytes(&sid[..8], 2).is_err());
    assert!(validate_sid_bytes(&[1, 255, 0, 0, 0, 0, 0, 0], 255).is_err());
    assert_eq!(
        validate_sid_header(&[1, 2, 0, 0, 0, 0, 0, 0], 16).unwrap(),
        16
    );
    assert!(validate_sid_header(&[1, 2, 0, 0], 16).is_err());
    assert!(validate_sid_header(&[1, 4, 0, 0, 0, 0, 0, 0], 16).is_err());
}

#[test]
fn overlapped_completion_barrier_requires_cancel_sync_and_exact_close() {
    use OverlappedEvent::*;
    assert!(validate_overlapped_trace(&[Pending, TimedOut, CancelIssued, Aborted, Closed]).is_ok());
    assert!(
        validate_overlapped_trace(&[Pending, TimedOut, CancelFailed, AlreadyComplete, Closed])
            .is_ok()
    );
    assert!(validate_overlapped_trace(&[Pending, Completed, Closed]).is_ok());
    for invalid in [
        vec![Pending, TimedOut, Closed],
        vec![Pending, TimedOut, CancelIssued, Closed],
        vec![Pending, Completed, Completed, Closed],
        vec![Pending, Completed, Closed, Closed],
        vec![Pending, TimedOut, CancelIssued, Aborted],
    ] {
        assert!(validate_overlapped_trace(&invalid).is_err());
    }
}

#[test]
fn auth_watchdog_aborts_only_when_armed_deadline_expires() {
    use std::time::{Duration, Instant};
    let now = Instant::now();
    assert_eq!(
        watchdog_decision(now + Duration::from_secs(1), now, true),
        WatchdogDecision::Wait
    );
    assert_eq!(watchdog_decision(now, now, true), WatchdogDecision::Abort);
    assert_eq!(
        watchdog_decision(now, now, false),
        WatchdogDecision::Disarmed
    );
}

#[test]
fn mutex_existing_descriptor_policy_is_exact_and_rejects_caller_acl() {
    use boothop_helper::windows::lock::validate_existing_mutex_dacl;
    assert!(validate_existing_mutex_dacl(
        boothop_helper::windows::OPERATION_MUTEX_DACL
    ));
    assert!(!validate_existing_mutex_dacl("D:P(A;;GA;;;WD)"));
    assert!(!validate_existing_mutex_dacl(""));
}

#[test]
fn request_id_mismatch_is_generic_before_operation_or_terminal_send() {
    use boothop_helper::windows::pipe::validate_request_id;
    let expected = boothop_protocol::RequestId::parse(valid_id()).unwrap();
    let actual = boothop_protocol::RequestId::parse("fedcba9876543210fedcba9876543210").unwrap();
    let error = validate_request_id(&expected, &actual).unwrap_err();
    assert!(matches!(
        error,
        Error::PlatformIo {
            operation: PlatformOperation::Security,
            ..
        }
    ));
}

#[test]
fn operation_deadline_is_single_absolute_budget_and_expires_without_reset() {
    use boothop_helper::windows::pipe::deadline_remaining;
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let deadline = start + Duration::from_secs(30);
    assert_eq!(
        deadline_remaining(deadline, start).unwrap(),
        Duration::from_secs(30)
    );
    assert_eq!(
        deadline_remaining(deadline, start + Duration::from_secs(11)).unwrap(),
        Duration::from_secs(19)
    );
    assert!(deadline_remaining(deadline, start + Duration::from_secs(31)).is_err());
}

#[test]
fn watchdog_worker_is_started_before_arm_returns_and_disarm_wins_before_deadline() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};

    let aborts = Arc::new(AtomicUsize::new(0));
    let hook = {
        let aborts = aborts.clone();
        Arc::new(move || {
            aborts.fetch_add(1, Ordering::SeqCst);
        })
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut watchdog = Watchdog::arm_with_abort(deadline, hook);
    assert!(watchdog.worker_started());
    assert_eq!(watchdog.state(), WatchdogState::Armed);
    watchdog.disarm();
    assert_eq!(watchdog.state(), WatchdogState::Disarmed);
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
}

#[test]
fn watchdog_expiry_is_atomic_at_equality_and_disarm_cannot_suppress_it() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};

    let now = Instant::now();
    assert_eq!(
        watchdog_worker_state(WatchdogState::Armed, now, now),
        WatchdogState::Expired
    );
    assert_eq!(
        watchdog_disarm_state(WatchdogState::Armed, now, now),
        WatchdogState::Expired
    );
    assert_eq!(
        watchdog_disarm_state(WatchdogState::Expired, now + Duration::from_secs(1), now),
        WatchdogState::Expired
    );

    let aborts = Arc::new(AtomicUsize::new(0));
    let hook = {
        let aborts = aborts.clone();
        Arc::new(move || {
            aborts.fetch_add(1, Ordering::SeqCst);
        })
    };
    let mut watchdog = Watchdog::arm_with_abort(Instant::now(), hook);
    for _ in 0..100 {
        if watchdog.state() == WatchdogState::Expired {
            break;
        }
        std::thread::yield_now();
    }
    assert_eq!(watchdog.state(), WatchdogState::Expired);
    watchdog.disarm();
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
}

#[test]
fn operation_deadline_is_carried_through_io_and_mutex_without_reset() {
    use boothop_helper::windows::pipe::{PipeIo, serve_authenticated_operation_until};
    use boothop_helper::windows::{OperationMutex, WaitOutcome, WindowsOperationGuard};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    struct Io {
        deadlines: Rc<RefCell<Vec<Instant>>>,
    }
    impl PipeIo for Io {
        fn receive_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, Error> {
            self.deadlines.borrow_mut().push(deadline);
            Ok(boothop_helper::protocol::encode_request_with_id(
                &boothop_protocol::RequestId::parse(valid_id()).unwrap(),
                boothop_core::Request::Inspect,
            )
            .unwrap())
        }
        fn send_frame(&mut self, _: &[u8], deadline: Instant) -> Result<(), Error> {
            self.deadlines.borrow_mut().push(deadline);
            Ok(())
        }
        fn close(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }
    struct MutexFake {
        deadline: Rc<RefCell<Option<Instant>>>,
    }
    impl OperationMutex for MutexFake {
        fn create(&mut self, _: &str, _: &str) -> Result<(), Error> {
            Ok(())
        }
        fn wait(&mut self, _: u32) -> Result<WaitOutcome, Error> {
            Ok(WaitOutcome::Acquired)
        }
        fn wait_until(&mut self, deadline: Instant) -> Result<WaitOutcome, Error> {
            *self.deadline.borrow_mut() = Some(deadline);
            Ok(WaitOutcome::Acquired)
        }
        fn release(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }
    let deadlines = Rc::new(RefCell::new(Vec::new()));
    let mutex_deadline = Rc::new(RefCell::new(None));
    let mut io = Io {
        deadlines: deadlines.clone(),
    };
    let args = HelperArgs::new(valid_id(), 42).unwrap();
    let evidence = AuthEvidence {
        pid: 42,
        token: token(false, false),
        image: image(GUI_IMAGE_PATH, false),
        session_id: 9,
    };
    let mut verifier = FakeVerifier::default();
    let operation_deadline = Instant::now() + Duration::from_secs(30);
    let result = serve_authenticated_operation_until::<_, _, MutexFake, _>(
        &mut io,
        &args,
        &mut verifier,
        evidence,
        operation_deadline,
        {
            let mutex_deadline = mutex_deadline.clone();
            move |deadline| {
                WindowsOperationGuard::acquire_until(
                    MutexFake {
                        deadline: mutex_deadline,
                    },
                    deadline,
                )
            }
        },
        |_| -> Result<
            boothop_platform::windows::WindowsPlatform<FakeStore, FakeFirmware, FakeReboot>,
            Error,
        > { Err(Error::Busy) },
    );
    assert_eq!(result, Ok(()));
    assert!(
        deadlines
            .borrow()
            .iter()
            .all(|deadline| *deadline == operation_deadline)
    );
    assert_eq!(*mutex_deadline.borrow(), Some(operation_deadline));
}

#[test]
fn authentication_deadline_is_carried_and_expiry_prevents_next_inspection() {
    use boothop_helper::windows::pipe::authenticate_peer_until;
    let args = HelperArgs::new(valid_id(), 42).unwrap();
    let mut fake = FakeVerifier::default();
    let expired = std::time::Instant::now() - std::time::Duration::from_secs(1);
    assert!(authenticate_peer_until(&mut fake, &args, expired).is_err());
    assert!(fake.calls.is_empty());
}

#[test]
fn typed_pipe_server_policy_binds_exact_request_id_and_user_sid() {
    use boothop_helper::windows::pipe::PipeServerSpec;
    let spec = PipeServerSpec::new(
        boothop_protocol::RequestId::parse(valid_id()).unwrap(),
        "S-1-5-21-1-2-3-1001",
    )
    .unwrap();
    assert_eq!(spec.name(), build_pipe_name(spec.request_id()));
    assert!(spec.dacl().unwrap().contains("S-1-5-21-1-2-3-1001"));
    assert!(
        PipeServerSpec::new(
            boothop_protocol::RequestId::parse(valid_id()).unwrap(),
            "S-1-5-x"
        )
        .is_err()
    );
    assert!(
        PipeServerSpec::new(
            boothop_protocol::RequestId::from_bytes([0; 16]),
            "S-1-5-21-1-2-3-1001"
        )
        .is_err()
    );
    assert!(
        validate_pipe_policy(PipePolicy {
            first_instance: true,
            reject_remote: true,
            dacl: "D:P(A;;GRGW;;;S-1-5-21-1-2-3-1001)(A;;GRGW;;;SY)(A;;GRGW;;;BA)",
        })
        .is_ok()
    );
    assert!(
        validate_pipe_policy(PipePolicy {
            first_instance: true,
            reject_remote: true,
            dacl: "D:P(A;;GRGW;;;S-1-5-21-1-2-3-1001)(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;WD)",
        })
        .is_err()
    );
}
