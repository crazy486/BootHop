#![cfg(target_os = "linux")]
use boothop_core::{Error, Request};
use boothop_helper::{
    dispatch::SessionIo,
    pipe::PipeSession,
    protocol::{decode_request, encode_request},
};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsFd, FromRawFd},
    time::{Duration, Instant},
};

fn pipe_pair() -> (File, File) {
    let mut fds = [0; 2];
    // SAFETY: libc initializes both descriptors in the supplied array.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: each descriptor is owned exactly once by the returned Files.
    unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
}
#[test]
fn isolated_pipes_accept_one_complete_request_and_bounded_output() {
    let (input, mut sender) = pipe_pair();
    let (mut receiver, output) = pipe_pair();
    let request = encode_request(Request::Inspect).unwrap();
    sender.write_all(&request).unwrap();
    drop(sender);
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
        let (input, mut sender) = pipe_pair();
        let (output, _receiver) = pipe_pair();
        sender.write_all(&bytes).unwrap();
        drop(sender);
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
    let (input, _sender) = pipe_pair();
    let (output, _receiver) = pipe_pair();
    let mut session = PipeSession::new(input.as_fd(), output.as_fd(), Instant::now()).unwrap();
    assert!(session.receive().is_err());
    assert!(session.send(b"hello").is_err());
}

#[test]
fn construction_rejects_regular_files_and_unix_sockets_before_nonblocking() {
    let input = tempfile_like();
    let output = tempfile_like();
    let error = PipeSession::new(
        input.as_fd(),
        output.as_fd(),
        Instant::now() + Duration::from_secs(1),
    )
    .err()
    .expect("regular files must be rejected");
    assert!(matches!(error, Error::PlatformIo { raw_code, .. } if raw_code == libc::ENOTSUP));

    let (input, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (_peer, output) = std::os::unix::net::UnixStream::pair().unwrap();
    let error = PipeSession::new(
        input.as_fd(),
        output.as_fd(),
        Instant::now() + Duration::from_secs(1),
    )
    .err()
    .expect("unix sockets must be rejected");
    assert!(matches!(error, Error::PlatformIo { raw_code, .. } if raw_code == libc::ENOTSUP));
}

fn tempfile_like() -> File {
    let path = std::env::temp_dir().join(format!("boothop-pipe-test-{}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let _ = std::fs::remove_file(path);
    file
}

#[test]
fn timeout_preserves_etimedout_for_empty_pipe() {
    let (input, _sender) = pipe_pair();
    let (output, _receiver) = pipe_pair();
    let mut session = PipeSession::new(input.as_fd(), output.as_fd(), Instant::now()).unwrap();
    assert!(
        matches!(session.receive(), Err(Error::PlatformIo { raw_code, .. }) if raw_code == libc::ETIMEDOUT)
    );
}

#[test]
fn closed_pipe_reader_reports_epipe_instead_of_generic_code() {
    let (input, _sender) = pipe_pair();
    let (receiver, output) = pipe_pair();
    drop(receiver);
    let mut session = PipeSession::new(
        input.as_fd(),
        output.as_fd(),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert!(matches!(
        session.send(b"hello"),
        Err(Error::PlatformIo { raw_code, .. }) if raw_code == libc::EPIPE
    ));
}
