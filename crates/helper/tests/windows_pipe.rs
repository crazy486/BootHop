use boothop_core::{Error, PlatformOperation};
use boothop_helper::windows::pipe::{
    AuthEvidence, DEFAULT_AUTH_DEADLINE, DEFAULT_OPERATION_DEADLINE, HelperArgs, ImageEvidence,
    PeerVerifier, PipePolicy, SelfEvidence, TokenEvidence, authenticate_peer,
    authenticate_peer_on_connection, build_pipe_name, parse_args, pipe_dacl_for_user_sid,
    validate_pipe_policy,
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
    }
}

#[derive(Default)]
struct FakeVerifier {
    self_evidence: Option<SelfEvidence>,
    peer: Option<AuthEvidence>,
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
        Ok(())
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
    }
    impl PipeIo for Io {
        fn receive_frame(&mut self, _: std::time::Instant) -> Result<Vec<u8>, Error> {
            self.events.borrow_mut().push("receive");
            Ok(boothop_helper::protocol::encode_request(boothop_core::Request::Inspect).unwrap())
        }
        fn send_frame(&mut self, _: &[u8], _: std::time::Instant) -> Result<(), Error> {
            self.events.borrow_mut().push("send");
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
    let mut io = Io {
        events: events.clone(),
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
