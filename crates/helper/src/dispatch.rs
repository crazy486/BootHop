//! One-shot trusted dispatch. Transport input is intent only.
use boothop_core::{Error, Os, Platform, PlatformOperation, Report, Request};
use boothop_protocol as protocol;

pub type SendResult<'a> = dyn FnMut(Result<Report, Error>) -> Result<(), Error> + 'a;
/// Implementations enforce a single 30s deadline across receive and send.
/// receive must return all input through EOF, rejecting more than one bounded frame.
pub trait SessionIo {
    fn receive(&mut self) -> Result<Vec<u8>, Error>;
    fn send(&mut self, bytes: &[u8]) -> Result<(), Error>;
}
pub fn run_linux(
    request: Request,
    platform: &mut impl Platform,
    send: &mut SendResult<'_>,
) -> Result<(), Error> {
    send(boothop_core::execute(request, Os::Linux, platform))
}

/// Trusted Windows dispatch. The host is fixed here and can never be supplied
/// by semantic GUI input.
pub fn run_windows(
    request: Request,
    platform: &mut impl Platform,
    send: &mut SendResult<'_>,
) -> Result<(), Error> {
    send(boothop_core::execute(request, Os::Windows, platform))
}
pub fn serve(
    euid: u32,
    io: &mut impl SessionIo,
    operation: impl FnOnce(Request, &mut SendResult<'_>) -> Result<(), Error>,
) -> Result<(), Error> {
    if euid != 0 {
        return Err(Error::PlatformIo {
            operation: PlatformOperation::Ipc,
            raw_code: 1,
        });
    }
    let hello = protocol::encode_hello();
    io.send(&hello)?;
    let envelope =
        protocol::decode_request_envelope(&io.receive()?).map_err(|_| Error::UnsupportedFormat)?;
    let request_id = envelope.request_id;
    let request = envelope.request;
    let mut sent = false;
    let mut send = |result| {
        if sent {
            return Err(Error::UnsupportedFormat);
        }
        sent = true; // No retry even when writing fails.
        let bytes = protocol::budgeted_response_with_id(&request_id, result, hello.len())
            .map_err(|_| Error::ResourceLimit)?;
        io.send(&bytes)
    };
    let outcome = operation(request, &mut send);
    match outcome {
        Err(error) if !sent => {
            let bytes = protocol::budgeted_response_with_id(&request_id, Err(error), hello.len())
                .map_err(|_| Error::ResourceLimit)?;
            io.send(&bytes)
        }
        Ok(()) if !sent => Err(Error::UnsupportedFormat),
        other => other,
    }
}

/// Windows transport hook. Authentication is completed before hello/request
/// bytes are accepted, and the callback is the only place allowed to build a
/// platform after that check. Native authentication remains a Task 7 seam.
pub fn serve_authenticated(
    io: &mut impl SessionIo,
    authenticate: impl FnOnce() -> Result<(), Error>,
    operation: impl FnOnce(Request, &mut SendResult<'_>) -> Result<(), Error>,
) -> Result<(), Error> {
    authenticate()?;
    let hello = protocol::encode_hello();
    io.send(&hello)?;
    let envelope =
        protocol::decode_request_envelope(&io.receive()?).map_err(|_| Error::UnsupportedFormat)?;
    let request_id = envelope.request_id;
    let mut sent = false;
    let mut send = |result| {
        if sent {
            return Err(Error::UnsupportedFormat);
        }
        sent = true;
        io.send(
            &protocol::budgeted_response_with_id(&request_id, result, hello.len())
                .map_err(|_| Error::ResourceLimit)?,
        )
    };
    let outcome = operation(envelope.request, &mut send);
    match outcome {
        Err(error) if !sent => io.send(
            &protocol::budgeted_response_with_id(&request_id, Err(error), hello.len())
                .map_err(|_| Error::ResourceLimit)?,
        ),
        Ok(()) if !sent => Err(Error::UnsupportedFormat),
        other => other,
    }
}

/// Complete one authenticated Windows operation. The operation guard is
/// acquired before platform construction and remains in scope until the
/// terminal `send` attempt has returned.
pub fn serve_windows<C, P>(
    io: &mut impl SessionIo,
    authenticate: impl FnOnce() -> Result<(), Error>,
    acquire: impl FnOnce() -> Result<crate::windows::WindowsOperationGuard<C>, Error>,
    construct: impl FnOnce(&crate::windows::WindowsOperationGuard<C>) -> Result<P, Error>,
) -> Result<(), Error>
where
    C: crate::windows::OperationMutex,
    P: Platform,
{
    authenticate()?;
    let hello = protocol::encode_hello();
    io.send(&hello)?;
    let envelope =
        protocol::decode_request_envelope(&io.receive()?).map_err(|_| Error::UnsupportedFormat)?;
    let request_id = envelope.request_id;
    let mut sent = false;
    let mut send = |result| {
        if sent {
            return Err(Error::UnsupportedFormat);
        }
        sent = true;
        io.send(
            &protocol::budgeted_response_with_id(&request_id, result, hello.len())
                .map_err(|_| Error::ResourceLimit)?,
        )
    };
    let guard = match acquire() {
        Ok(guard) => guard,
        Err(error) => return send(Err(error)),
    };
    let outcome = match construct(&guard) {
        Ok(mut platform) => run_windows(envelope.request, &mut platform, &mut send),
        Err(error) => send(Err(error)),
    };
    // `guard` is intentionally dropped only after terminal response attempt.
    outcome
}

#[cfg(target_os = "linux")]
pub fn production(request: Request, send: &mut SendResult<'_>) -> Result<(), Error> {
    crate::lock::with_linux_operation(|store| {
        let mut platform = boothop_platform::linux::LinuxPlatform::system(store);
        run_linux(request, &mut platform, send)
    })
}
