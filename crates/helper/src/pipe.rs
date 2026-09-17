//! Bounded nonblocking Unix pipe operations, shared by the two process endpoints.
use crate::{dispatch::SessionIo, protocol::MAX_BYTES};
use boothop_core::{Error, PlatformOperation};
use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd, RawFd},
    time::Instant,
};

fn failure(operation: PlatformOperation, error: io::Error) -> Error {
    let raw_code = error.raw_os_error().unwrap_or_else(|| match error.kind() {
        io::ErrorKind::TimedOut => libc::ETIMEDOUT,
        io::ErrorKind::WriteZero => libc::EPIPE,
        _ => libc::EIO,
    });
    Error::PlatformIo {
        operation,
        raw_code,
    }
}

pub struct PipeSession<'a> {
    input: BorrowedFd<'a>,
    output: BorrowedFd<'a>,
    deadline: Instant,
}
impl<'a> PipeSession<'a> {
    pub fn new(
        input: BorrowedFd<'a>,
        output: BorrowedFd<'a>,
        deadline: Instant,
    ) -> Result<Self, Error> {
        validate_pipe(input.as_raw_fd()).map_err(|e| failure(PlatformOperation::Ipc, e))?;
        validate_pipe(output.as_raw_fd()).map_err(|e| failure(PlatformOperation::Ipc, e))?;
        nonblocking(input.as_raw_fd()).map_err(|e| failure(PlatformOperation::Ipc, e))?;
        nonblocking(output.as_raw_fd()).map_err(|e| failure(PlatformOperation::Ipc, e))?;
        Ok(Self {
            input,
            output,
            deadline,
        })
    }
}
impl SessionIo for PipeSession<'_> {
    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        loop {
            wait(
                &mut [libc::pollfd {
                    fd: self.input.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                }],
                self.deadline,
            )
            .map_err(|e| failure(PlatformOperation::Ipc, e))?;
            let mut buf = [0; 4096];
            match read(self.input.as_raw_fd(), &mut buf) {
                Ok(0) => return Ok(out),
                Ok(n) => {
                    if out.len() + n > MAX_BYTES {
                        return Err(Error::ResourceLimit);
                    }
                    out.extend_from_slice(&buf[..n]);
                    if out.len() >= 4 {
                        let size = u32::from_le_bytes(out[..4].try_into().unwrap()) as usize;
                        if size > MAX_BYTES - 4 || out.len() > size + 4 {
                            return Err(Error::ResourceLimit);
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(failure(PlatformOperation::Ipc, e)),
            }
        }
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        write_all(self.output.as_raw_fd(), bytes, self.deadline)
            .map_err(|e| failure(PlatformOperation::Ipc, e))
    }
}
fn validate_pipe(fd: RawFd) -> io::Result<()> {
    // SAFETY: fstat writes one stat record for this borrowed descriptor.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
    }
    Ok(())
}

pub fn nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl only changes flags on the borrowed, live descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub fn wait(fds: &mut [libc::pollfd], deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ETIMEDOUT))?;
        let ms = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        // SAFETY: poll receives a valid mutable slice for this call.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
pub fn read(fd: RawFd, bytes: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the writable slice and borrowed descriptor remain valid for read.
    let result = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}
pub fn write_all(fd: RawFd, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        wait(
            &mut [libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            }],
            deadline,
        )?;
        // SAFETY: the immutable slice and borrowed descriptor remain valid for write.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::Error::from_raw_os_error(libc::EPIPE));
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::failure;
    use boothop_core::{Error, PlatformOperation};
    use std::io;

    #[test]
    fn failure_preserves_explicit_ebadf() {
        let error = failure(
            PlatformOperation::Ipc,
            io::Error::from_raw_os_error(libc::EBADF),
        );
        assert!(matches!(
            error,
            Error::PlatformIo { raw_code, .. } if raw_code == libc::EBADF
        ));
    }
}
