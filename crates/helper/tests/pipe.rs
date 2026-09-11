#![cfg(target_os = "linux")]
use boothop_core::{Error, Request};
use boothop_helper::{
    dispatch::SessionIo,
    pipe::PipeSession,
    protocol::{decode_request, encode_request},
};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::{fd::AsFd, unix::net::UnixStream},
    time::{Duration, Instant},
};
#[test]
fn isolated_pipes_accept_one_complete_request_and_bounded_output() {
    let (input, mut sender) = UnixStream::pair().unwrap();
    let (output, mut receiver) = UnixStream::pair().unwrap();
    let request = encode_request(Request::Inspect).unwrap();
    sender.write_all(&request).unwrap();
    sender.shutdown(Shutdown::Write).unwrap();
    let mut session = PipeSession::new(
        input.as_fd(),
        output.as_fd(),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(
        decode_request(&session.receive().unwrap()),
        Ok(Request::Inspect)
    );
    session.send(b"hello").unwrap();
    let mut bytes = [0; 5];
    receiver.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"hello");
}
#[test]
fn isolated_pipes_reject_second_request_and_oversized_prefix() {
    for bytes in [
        encode_request(Request::Inspect).unwrap().repeat(2),
        65533_u32.to_le_bytes().to_vec(),
    ] {
        let (input, mut sender) = UnixStream::pair().unwrap();
        let (output, _receiver) = UnixStream::pair().unwrap();
        sender.write_all(&bytes).unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        let mut session = PipeSession::new(
            input.as_fd(),
            output.as_fd(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(session.receive(), Err(Error::ResourceLimit));
    }
}
#[test]
fn expired_deadline_covers_read_and_write_without_waiting() {
    let (input, _sender) = UnixStream::pair().unwrap();
    let (output, _receiver) = UnixStream::pair().unwrap();
    let mut session = PipeSession::new(input.as_fd(), output.as_fd(), Instant::now()).unwrap();
    assert!(session.receive().is_err());
    assert!(session.send(b"hello").is_err());
}
