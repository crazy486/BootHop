#![cfg(target_os = "linux")]

use boothop_core::{Error, PlatformOperation};
use boothop_helper::dispatch::{self, SessionIo};
use boothop_helper::protocol::{
    LifecycleOperation, LifecycleStatus, RequestId, decode_hello,
    decode_lifecycle_response_envelope, encode_lifecycle_request_with_id, encode_request,
};
use std::cell::Cell;

struct Io {
    input: Vec<u8>,
    output: Vec<Vec<u8>>,
    fail_terminal_send: bool,
}

impl Io {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            output: Vec::new(),
            fail_terminal_send: false,
        }
    }
}

impl SessionIo for Io {
    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.input.clone())
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.output.push(bytes.to_vec());
        if self.fail_terminal_send && self.output.len() == 2 {
            return Err(Error::PlatformIo {
                operation: PlatformOperation::Ipc,
                raw_code: 32,
            });
        }
        Ok(())
    }
}

fn request(operation: LifecycleOperation) -> (RequestId, Vec<u8>) {
    let id = RequestId::parse("0123456789abcdef0123456789abcde1").unwrap();
    let frame = encode_lifecycle_request_with_id(&id, operation).unwrap();
    (id, frame)
}

#[test]
fn lifecycle_status_is_returned_with_the_request_correlation_id() {
    let (id, frame) = request(LifecycleOperation::ProvisionArchEntry);
    let mut io = Io::new(frame);
    let called = Cell::new(false);

    dispatch::serve_lifecycle(0, &mut io, |operation| {
        called.set(true);
        assert_eq!(operation, LifecycleOperation::ProvisionArchEntry);
        LifecycleStatus::AlreadyPresent
    })
    .unwrap();

    assert!(called.get());
    assert_eq!(io.output.len(), 2);
    decode_hello(&io.output[0]).unwrap();
    let response = decode_lifecycle_response_envelope(&io.output[1]).unwrap();
    assert_eq!(response.request_id, id);
    assert_eq!(response.status, LifecycleStatus::AlreadyPresent);
}

#[test]
fn malformed_and_ordinary_frames_are_rejected_before_callback() {
    let ordinary = encode_request(boothop_core::Request::Inspect).unwrap();
    for input in [vec![1, 2, 3], ordinary] {
        let mut io = Io::new(input);
        let called = Cell::new(false);

        assert_eq!(
            dispatch::serve_lifecycle(0, &mut io, |_| {
                called.set(true);
                LifecycleStatus::Succeeded
            }),
            Err(Error::UnsupportedFormat)
        );

        assert!(!called.get());
        assert_eq!(io.output.len(), 1, "only hello is sent for invalid input");
        decode_hello(&io.output[0]).unwrap();
    }
}

#[test]
fn non_root_is_rejected_before_io_or_callback() {
    let mut io = Io::new(Vec::new());
    let called = Cell::new(false);

    assert_eq!(
        dispatch::serve_lifecycle(1000, &mut io, |_| {
            called.set(true);
            LifecycleStatus::Succeeded
        }),
        Err(Error::PlatformIo {
            operation: PlatformOperation::Ipc,
            raw_code: 1,
        })
    );

    assert!(!called.get());
    assert!(io.output.is_empty());
}

#[test]
fn terminal_response_is_attempted_once_even_when_send_fails() {
    let (_, frame) = request(LifecycleOperation::UninstallArchEntry);
    let mut io = Io::new(frame);
    io.fail_terminal_send = true;
    let called = Cell::new(false);

    assert_eq!(
        dispatch::serve_lifecycle(0, &mut io, |_| {
            called.set(true);
            LifecycleStatus::NotPresent
        }),
        Err(Error::PlatformIo {
            operation: PlatformOperation::Ipc,
            raw_code: 32,
        })
    );

    assert!(called.get());
    assert_eq!(io.output.len(), 2);
}
