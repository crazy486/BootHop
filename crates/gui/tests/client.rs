use boothop_core::{Error, Request};
use boothop_gui::helper_client::{
    Boundary, ClientError, Event, HelperClient, SpawnSpec, TransportError,
};
use boothop_protocol::encode_hello;
use std::{collections::VecDeque, time::Duration};
struct Fake {
    events: VecDeque<Result<Event, TransportError>>,
    specs: Vec<SpawnSpec>,
    writes: Vec<Vec<u8>>,
    deadlines: Vec<Duration>,
    now: Duration,
}
impl Fake {
    fn new(events: Vec<Result<Event, TransportError>>) -> Self {
        Self {
            events: events.into(),
            specs: vec![],
            writes: vec![],
            deadlines: vec![],
            now: Duration::ZERO,
        }
    }
}
impl Boundary for Fake {
    fn now(&self) -> Duration {
        self.now
    }
    fn spawn(&mut self, spec: &SpawnSpec) -> Result<(), TransportError> {
        self.specs.push(spec.clone());
        Ok(())
    }
    fn next(&mut self, deadline: Duration) -> Result<Event, TransportError> {
        self.deadlines.push(deadline);
        self.now += Duration::from_secs(2);
        self.events
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }
    fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), TransportError> {
        self.deadlines.push(deadline);
        self.writes.push(bytes.to_vec());
        Ok(())
    }
    fn stop(&mut self) {}
}

fn json_frame(json: &str) -> Vec<u8> {
    let mut bytes = (json.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(json.as_bytes());
    bytes
}
#[test]
fn noncanonical_hello_never_enters_send_phase() {
    let mut client = HelperClient::new(Fake::new(vec![Ok(Event::Stdout(json_frame("[1,true]")))]));
    assert_eq!(
        client.run(Request::Inspect),
        Err(ClientError::BeforeSend(TransportError::Protocol))
    );
    assert!(client.into_boundary().writes.is_empty());
}
#[test]
fn noncanonical_response_after_send_is_unknown_not_a_domain_result() {
    for json in [
        r#"{"protocol_version":1,"result":{"Err":{"StoreDurabilityUnknown":[5]}}}"#,
        r#"{"protocol_version":1,"result":{"Ok":[[],"Missing",[],[]]}}"#,
        r#"{"protocol_version":1,"result":{"Err":{"Busy":null}}}"#,
    ] {
        let mut client = HelperClient::new(Fake::new(vec![
            Ok(Event::Stdout(encode_hello())),
            Ok(Event::Stdout(json_frame(json))),
            Ok(Event::Exit(0)),
        ]));
        assert_eq!(
            client.run(Request::Inspect),
            Err(ClientError::UnknownAfterSend(TransportError::Protocol))
        );
        let fake = client.into_boundary();
        assert_eq!(fake.writes.len(), 1);
        assert_eq!(fake.specs.len(), 1);
    }
}
#[test]
fn fixed_spawn_environment_and_126_127_are_presend_only() {
    for (code, expected) in [
        (126, ClientError::Cancelled),
        (127, ClientError::AuthorizationOrLaunchFailed),
        (1, ClientError::BeforeSend(TransportError::Exit)),
    ] {
        let mut client = HelperClient::new(Fake::new(vec![Ok(Event::Exit(code))]));
        assert_eq!(client.run(Request::Inspect), Err(expected));
        let fake = client.into_boundary();
        assert_eq!(
            fake.specs,
            vec![SpawnSpec {
                program: "/usr/bin/pkexec",
                args: vec![
                    "--disable-internal-agent",
                    "/usr/lib/boothop/boothop-helper"
                ],
                environment: vec![("LC_ALL", "C")]
            }]
        );
        assert!(fake.writes.is_empty());
        assert_eq!(fake.deadlines, [Duration::from_secs(120)]);
    }
}
#[test]
fn hello_then_timeout_is_unknown_without_retry() {
    let mut client = HelperClient::new(Fake::new(vec![
        Ok(Event::Stdout(encode_hello())),
        Err(TransportError::Timeout),
    ]));
    assert_eq!(
        client.run(Request::Switch {
            os: boothop_core::Os::Windows
        }),
        Err(ClientError::UnknownAfterSend(TransportError::Timeout))
    );
    let fake = client.into_boundary();
    assert_eq!(fake.specs.len(), 1);
    assert_eq!(fake.writes.len(), 1);
    assert_eq!(
        fake.deadlines,
        [
            Duration::from_secs(120),
            Duration::from_secs(32),
            Duration::from_secs(32)
        ]
    );
}
#[test]
fn valid_domain_error_is_preserved() {
    let response =
        boothop_protocol::encode_response(Err(Error::StoreDurabilityUnknown { raw_code: 5 }))
            .unwrap();
    let mut client = HelperClient::new(Fake::new(vec![
        Ok(Event::Stdout(encode_hello())),
        Ok(Event::Stdout(response)),
        Ok(Event::Exit(0)),
    ]));
    assert_eq!(
        client.run(Request::Inspect),
        Err(ClientError::Domain(Error::StoreDurabilityUnknown {
            raw_code: 5
        }))
    );
}

#[test]
fn before_hello_failures_never_send() {
    for events in [
        vec![Err(TransportError::Launch)],
        vec![Err(TransportError::Timeout)],
        vec![Err(TransportError::Io)],
        vec![Ok(Event::Stdout(vec![0; 4]))],
        vec![Ok(Event::Stdout(65533_u32.to_le_bytes().to_vec()))],
        vec![Ok(Event::Stderr(vec![0; 65537]))],
    ] {
        let mut client = HelperClient::new(Fake::new(events));
        assert!(matches!(
            client.run(Request::Inspect),
            Err(ClientError::BeforeSend(_))
        ));
        let fake = client.into_boundary();
        assert!(fake.writes.is_empty());
        assert_eq!(fake.specs.len(), 1);
    }
}
#[test]
fn all_postsend_failure_shapes_remain_unknown_and_never_retry() {
    for tail in [
        vec![Err(TransportError::Io)],
        vec![Err(TransportError::Timeout)],
        vec![Ok(Event::Exit(126))],
        vec![Ok(Event::Exit(127))],
        vec![Ok(Event::Exit(-1))],
        vec![Ok(Event::Exit(0))],
        vec![Ok(Event::Stdout(vec![0; 4])), Ok(Event::Exit(0))],
        vec![Ok(Event::Stdout(65533_u32.to_le_bytes().to_vec()))],
        vec![Ok(Event::Stdout(
            boothop_protocol::encode_response(Err(Error::Busy))
                .unwrap()
                .repeat(2),
        ))],
        vec![Ok(Event::Stderr(vec![0; 65536]))],
    ] {
        let mut events = vec![Ok(Event::Stdout(encode_hello()))];
        events.extend(tail);
        let mut client = HelperClient::new(Fake::new(events));
        assert!(matches!(
            client.run(Request::Inspect),
            Err(ClientError::UnknownAfterSend(_))
        ));
        let fake = client.into_boundary();
        assert_eq!(fake.writes.len(), 1);
        assert_eq!(fake.specs.len(), 1);
    }
}
#[test]
fn fragmented_frames_and_stderr_share_one_exact_budget() {
    let hello = encode_hello();
    let result = Err(Error::IdentityMismatch);
    let response = boothop_protocol::encode_response(result).unwrap();
    for excess in [0, 1] {
        let stderr = vec![0; 65536 - hello.len() - response.len() + excess];
        let mut client = HelperClient::new(Fake::new(vec![
            Ok(Event::Stdout(hello[..2].to_vec())),
            Ok(Event::Stderr(stderr)),
            Ok(Event::Stdout(hello[2..].to_vec())),
            Ok(Event::Stdout(response[..3].to_vec())),
            Ok(Event::Stdout(response[3..].to_vec())),
            Ok(Event::Exit(0)),
        ]));
        let expected = if excess == 0 {
            ClientError::Domain(Error::IdentityMismatch)
        } else {
            ClientError::UnknownAfterSend(TransportError::ResourceLimit)
        };
        assert_eq!(client.run(Request::Inspect), Err(expected));
    }
}
#[test]
fn absolute_deadline_is_not_extended_by_progress() {
    let mut events = vec![];
    for _ in 0..61 {
        events.push(Ok(Event::Stderr(vec![0])));
    }
    let mut client = HelperClient::new(Fake::new(events));
    assert_eq!(
        client.run(Request::Inspect),
        Err(ClientError::BeforeSend(TransportError::Timeout))
    );
    assert!(client.into_boundary().writes.is_empty());
    let mut events = vec![Ok(Event::Stdout(encode_hello()))];
    for _ in 0..16 {
        events.push(Ok(Event::Stderr(vec![0])));
    }
    let mut client = HelperClient::new(Fake::new(events));
    assert_eq!(
        client.run(Request::Inspect),
        Err(ClientError::UnknownAfterSend(TransportError::Timeout))
    );
    assert_eq!(client.into_boundary().writes.len(), 1);
}
#[test]
fn success_returns_only_the_received_stages() {
    let report = boothop_core::Report {
        candidates: vec![],
        record: boothop_core::RecordDiagnostic::Missing,
        stages: vec![
            boothop_core::Stage::RebootUnknown,
            boothop_core::Stage::ResidualPossible,
        ],
        diagnostics: vec![],
    };
    let response = boothop_protocol::encode_response(Ok(report.clone())).unwrap();
    let mut client = HelperClient::new(Fake::new(vec![
        Ok(Event::Stdout(encode_hello())),
        Ok(Event::Stdout(response)),
        Ok(Event::Exit(0)),
    ]));
    assert_eq!(client.run(Request::Inspect), Ok(report));
}
#[test]
fn confirmed_incomplete_send_is_presend_and_cleanup_runs_once() {
    struct FailingSend {
        fake: Fake,
        stops: usize,
    }
    impl Boundary for FailingSend {
        fn now(&self) -> Duration {
            self.fake.now()
        }
        fn spawn(&mut self, s: &SpawnSpec) -> Result<(), TransportError> {
            self.fake.spawn(s)
        }
        fn next(&mut self, d: Duration) -> Result<Event, TransportError> {
            self.fake.next(d)
        }
        fn send(&mut self, _: &[u8], _: Duration) -> Result<(), TransportError> {
            Err(TransportError::Io)
        }
        fn stop(&mut self) {
            self.stops += 1;
        }
    }
    let mut client = HelperClient::new(FailingSend {
        fake: Fake::new(vec![Ok(Event::Stdout(encode_hello()))]),
        stops: 0,
    });
    assert_eq!(
        client.run(Request::Inspect),
        Err(ClientError::BeforeSend(TransportError::Io))
    );
    let boundary = client.into_boundary();
    assert_eq!(boundary.stops, 1);
    assert_eq!(boundary.fake.specs.len(), 1);
}
