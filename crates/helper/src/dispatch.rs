//! One-shot trusted dispatch. Transport input is intent only.
use boothop_core::{Error, Os, Platform, Report, Request};
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
pub fn serve(
    euid: u32,
    io: &mut impl SessionIo,
    operation: impl FnOnce(Request, &mut SendResult<'_>) -> Result<(), Error>,
) -> Result<(), Error> {
    if euid != 0 {
        return Err(Error::PlatformIo {
            operation: "ipc".into(),
            raw_code: 1,
        });
    }
    let hello = protocol::encode_hello();
    io.send(&hello)?;
    let request = protocol::decode_request(&io.receive()?).map_err(|_| Error::UnsupportedFormat)?;
    let mut sent = false;
    let mut send = |result| {
        if sent {
            return Err(Error::UnsupportedFormat);
        }
        sent = true; // No retry even when writing fails.
        let bytes =
            protocol::budgeted_response(result, hello.len()).map_err(|_| Error::ResourceLimit)?;
        io.send(&bytes)
    };
    let outcome = operation(request, &mut send);
    match outcome {
        Err(error) if !sent => {
            let bytes = protocol::budgeted_response(Err(error), hello.len())
                .map_err(|_| Error::ResourceLimit)?;
            io.send(&bytes)
        }
        Ok(()) if !sent => Err(Error::UnsupportedFormat),
        other => other,
    }
}

#[cfg(target_os = "linux")]
pub fn production(request: Request, send: &mut SendResult<'_>) -> Result<(), Error> {
    crate::lock::with_linux_operation(|store| {
        let mut platform = boothop_platform::linux::LinuxPlatform::system(store);
        run_linux(request, &mut platform, send)
    })
}
