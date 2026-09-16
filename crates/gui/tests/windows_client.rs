use boothop_core::Request;
use boothop_gui::helper_client::windows::{
    GUI_EXECUTION_LEVEL, GUI_IMAGE_PATH, HELPER_IMAGE_PATH, HELPER_RUNAS_VERB, PeerIdentity,
    WindowsBoundary, WindowsClient, WindowsLaunchSpec, WindowsPipeSpec, authenticate_helper,
};
use boothop_gui::helper_client::{ClientError, Event, TransportError};
use boothop_protocol::{RequestId, decode_request_envelope, encode_hello, encode_response};
use std::{collections::VecDeque, time::Duration};

struct Fake {
    events: VecDeque<Result<Event, TransportError>>,
    launches: Vec<WindowsLaunchSpec>,
    pipes: Vec<WindowsPipeSpec>,
    writes: Vec<Vec<u8>>,
    deadlines: Vec<Duration>,
    now: Duration,
    start_error: Option<TransportError>,
    mismatch_response: bool,
}

impl Fake {
    fn new(events: Vec<Result<Event, TransportError>>) -> Self {
        Self {
            events: events.into(),
            launches: vec![],
            pipes: vec![],
            writes: vec![],
            deadlines: vec![],
            now: Duration::ZERO,
            start_error: None,
            mismatch_response: false,
        }
    }
}

impl WindowsBoundary for Fake {
    fn now(&self) -> Duration {
        self.now
    }
    fn next(&mut self, deadline: Duration) -> Result<Event, TransportError> {
        self.deadlines.push(deadline);
        self.events
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }
    fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), TransportError> {
        self.deadlines.push(deadline);
        self.writes.push(bytes.to_vec());
        if let Ok(request) = decode_request_envelope(bytes) {
            let mut events = VecDeque::new();
            while let Some(event) = self.events.pop_front() {
                events.push_back(match event {
                    Ok(Event::Stdout(frame)) => {
                        if let Ok(response) = boothop_protocol::decode_response_envelope(&frame) {
                            Ok(Event::Stdout(
                                boothop_protocol::encode_response_with_id(
                                    &if self.mismatch_response {
                                        RequestId::parse("fedcba9876543210fedcba9876543210")
                                            .unwrap()
                                    } else {
                                        request.request_id.clone()
                                    },
                                    response.result,
                                )
                                .unwrap(),
                            ))
                        } else {
                            Ok(Event::Stdout(frame))
                        }
                    }
                    other => other,
                });
            }
            self.events = events;
        }
        Ok(())
    }
    fn stop(&mut self) {}
    fn start(&mut self, id: &RequestId) -> Result<(), TransportError> {
        if let Some(error) = self.start_error.take() {
            return Err(error);
        }
        self.pipes.push(WindowsPipeSpec::for_request(
            id.clone(),
            "S-1-5-21-1-2-3-1001",
        ));
        self.launches
            .push(WindowsLaunchSpec::for_request(id.clone(), 42));
        Ok(())
    }
}

#[test]
fn response_request_id_mismatch_is_unknown_after_send_without_retry() {
    let response = encode_response(Err(boothop_core::Error::Busy)).unwrap();
    let mut fake = Fake::new(vec![
        Ok(Event::Stdout(encode_hello())),
        Ok(Event::Stdout(response)),
        Ok(Event::Exit(0)),
    ]);
    fake.mismatch_response = true;
    let mut client = WindowsClient::new(fake);
    assert_eq!(
        client.run(Request::Inspect),
        Err(ClientError::UnknownAfterSend(TransportError::Protocol))
    );
    let fake = client.into_boundary();
    assert_eq!(fake.writes.len(), 1);
}

#[test]
fn fixed_windows_launch_and_pipe_specs_bind_request_id_without_generic_paths() {
    let id = RequestId::parse("0123456789abcdef0123456789abcde1").unwrap();
    let launch = WindowsLaunchSpec::for_request(id.clone(), 42);
    assert_eq!(launch.program(), HELPER_IMAGE_PATH);
    assert_eq!(launch.verb(), HELPER_RUNAS_VERB);
    assert_eq!(launch.gui_execution_level(), GUI_EXECUTION_LEVEL);
    assert!(launch.see_mask_nocloseprocess());
    assert_eq!(
        launch.args(),
        vec![
            "--version=2".to_owned(),
            format!("--request-id={}", id.as_str()),
            "--gui-pid=42".to_owned()
        ]
    );
    assert_eq!(launch.gui_image(), GUI_IMAGE_PATH);
    assert_eq!(
        WindowsPipeSpec::for_request(id.clone(), "S-1-5-21-1-2-3-1001").name(),
        format!("\\\\.\\pipe\\BootHop.{}", id.as_str())
    );
    assert!(
        WindowsPipeSpec::for_request(id, "S-1-5-21-1-2-3-1001")
            .dacl()
            .contains("S-1-5-21-1-2-3-1001")
    );
}

#[test]
fn windows_client_reports_cancel_and_launch_failure_before_send() {
    for (error, expected) in [
        (TransportError::Cancelled, ClientError::Cancelled),
        (
            TransportError::Launch,
            ClientError::BeforeSend(TransportError::Launch),
        ),
    ] {
        let mut fake = Fake::new(vec![]);
        fake.start_error = Some(error);
        let mut client = WindowsClient::new(fake);
        assert_eq!(client.run(Request::Inspect), Err(expected));
        let fake = client.into_boundary();
        assert!(fake.writes.is_empty());
    }
}

#[test]
fn windows_client_authenticates_before_send_and_maps_post_send_failures_unknown() {
    let mut client = WindowsClient::new(Fake::new(vec![
        Ok(Event::Stdout(encode_hello())),
        Err(TransportError::Timeout),
    ]));
    assert_eq!(
        client.run(Request::Inspect),
        Err(ClientError::UnknownAfterSend(TransportError::Timeout))
    );
    let fake = client.into_boundary();
    assert_eq!(fake.writes.len(), 1);
    let request = decode_request_envelope(&fake.writes[0]).unwrap();
    assert_ne!(
        request.request_id.as_str(),
        "00000000000000000000000000000000"
    );
    assert_eq!(
        fake.deadlines,
        [
            Duration::from_secs(120),
            Duration::from_secs(30),
            Duration::from_secs(30)
        ]
    );
}

#[test]
fn windows_client_sends_exactly_one_request_and_accepts_correlated_response() {
    let response = encode_response(Err(boothop_core::Error::Busy)).unwrap();
    let mut client = WindowsClient::new(Fake::new(vec![
        Ok(Event::Stdout(encode_hello())),
        Ok(Event::Stdout(response)),
        Ok(Event::Exit(0)),
    ]));
    assert_eq!(
        client.run(Request::Inspect),
        Err(ClientError::Domain(boothop_core::Error::Busy))
    );
    let fake = client.into_boundary();
    assert_eq!(fake.writes.len(), 1);
    assert_eq!(fake.launches.len(), 1);
    assert_eq!(fake.pipes.len(), 1);
}

#[test]
fn helper_identity_requires_pid_image_elevation_integrity_and_session_but_not_equal_user() {
    let valid = PeerIdentity {
        pid: 99,
        elevated: true,
        high_integrity: true,
        image: HELPER_IMAGE_PATH.to_owned(),
        session_id: 7,
    };
    assert!(authenticate_helper(&valid, 99, 7).is_ok());
    for mutate in [
        PeerIdentity {
            pid: 100,
            ..valid.clone()
        },
        PeerIdentity {
            elevated: false,
            ..valid.clone()
        },
        PeerIdentity {
            high_integrity: false,
            ..valid.clone()
        },
        PeerIdentity {
            image: GUI_IMAGE_PATH.to_owned(),
            ..valid.clone()
        },
        PeerIdentity {
            session_id: 8,
            ..valid.clone()
        },
    ] {
        assert_eq!(
            authenticate_helper(&mutate, 99, 7),
            Err(TransportError::Authentication)
        );
    }
}
