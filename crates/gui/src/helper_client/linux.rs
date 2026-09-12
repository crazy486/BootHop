//! Explicit production process boundary. Construction alone has no OS side effects.
use super::{Boundary, Event, HelperClient, SpawnSpec, TransportError};
use std::{
    io,
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

mod pipe {
    use std::{io, os::fd::RawFd, time::Instant};
    pub fn nonblocking(fd: RawFd) -> io::Result<()> {
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
            let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if n < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            if n == 0 {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            bytes = &bytes[n as usize..];
        }
        Ok(())
    }
}

pub struct SystemProcess {
    epoch: Instant,
    child: Option<Child>,
}
impl Default for SystemProcess {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            child: None,
        }
    }
}
impl HelperClient<SystemProcess> {
    pub fn system() -> Self {
        Self::new(SystemProcess::default())
    }
}
fn error(e: io::Error) -> TransportError {
    if e.kind() == io::ErrorKind::TimedOut {
        TransportError::Timeout
    } else {
        TransportError::Io
    }
}
impl Boundary for SystemProcess {
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
    fn spawn(&mut self, spec: &SpawnSpec) -> Result<(), TransportError> {
        if self.child.is_some() {
            return Err(TransportError::Launch);
        }
        // Absolute executable, no shell/PATH lookup; inherited environment is discarded.
        let child = Command::new(spec.program)
            .args(&spec.args)
            .env_clear()
            .envs(spec.environment.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| TransportError::Launch)?;
        self.child = Some(child);
        let child = self.child.as_ref().unwrap();
        for fd in [
            child.stdin.as_ref().unwrap().as_raw_fd(),
            child.stdout.as_ref().unwrap().as_raw_fd(),
            child.stderr.as_ref().unwrap().as_raw_fd(),
        ] {
            pipe::nonblocking(fd).map_err(error)?;
        }
        Ok(())
    }
    fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), TransportError> {
        let child = self.child.as_mut().ok_or(TransportError::Io)?;
        let stdin = child.stdin.take().ok_or(TransportError::Io)?;
        pipe::write_all(stdin.as_raw_fd(), bytes, self.epoch + deadline).map_err(error)
    }
    fn next(&mut self, deadline: Duration) -> Result<Event, TransportError> {
        let child = self.child.as_mut().ok_or(TransportError::Io)?;
        let end = self.epoch + deadline;
        loop {
            if Instant::now() >= end {
                return Err(TransportError::Timeout);
            }
            let mut fds = [
                libc::pollfd {
                    fd: child.stdout.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: child.stderr.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            if fds.iter().all(|f| f.fd == -1) {
                if let Some(status) = child.try_wait().map_err(error)? {
                    return Ok(Event::Exit(status.code().unwrap_or(-1)));
                }
                // Bounded poll tick permits observing exit without blocking wait().
                let tick = (Instant::now() + Duration::from_millis(10)).min(end);
                match pipe::wait(&mut [], tick) {
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                    Err(e) => return Err(error(e)),
                    Ok(()) => continue,
                }
            }
            pipe::wait(&mut fds, end).map_err(error)?;
            for (index, fd) in fds.iter().enumerate() {
                if fd.revents == 0 {
                    continue;
                }
                let mut bytes = vec![0; 4096];
                match pipe::read(fd.fd, &mut bytes) {
                    Ok(0) => {
                        if index == 0 {
                            child.stdout.take();
                        } else {
                            child.stderr.take();
                        }
                    }
                    Ok(n) => {
                        bytes.truncate(n);
                        return Ok(if index == 0 {
                            Event::Stdout(bytes)
                        } else {
                            Event::Stderr(bytes)
                        });
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                        ) => {}
                    Err(e) => return Err(error(e)),
                }
            }
        }
    }
    fn stop(&mut self) {
        if let Some(child) = self.child.take() {
            cleanup_child(child);
        }
    }
}
/// A pkexec child may now be root and reject our signal. Never synchronously
/// wait for it after the client deadline; its operation may still be running.
trait ChildCleanup {
    fn terminate(&mut self);
    fn finished(&mut self) -> bool;
    fn reap_later(self);
}
fn cleanup_child(mut child: impl ChildCleanup) {
    child.terminate();
    if !child.finished() {
        child.reap_later();
    }
}
impl ChildCleanup for Child {
    fn terminate(&mut self) {
        self.stdin.take();
        self.stdout.take();
        self.stderr.take();
        let _ = self.kill();
    }
    fn finished(&mut self) -> bool {
        self.try_wait().is_ok_and(|status| status.is_some())
    }
    fn reap_later(mut self) {
        // Drop the JoinHandle to detach. Failure to create the reaper cannot
        // justify blocking the caller or inventing a confirmed operation result.
        let _ = std::thread::Builder::new()
            .name("boothop-reaper".into())
            .spawn(move || {
                let _ = self.wait();
            });
    }
}
impl Drop for SystemProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    struct RootChild(Rc<RefCell<Vec<&'static str>>>);
    impl ChildCleanup for RootChild {
        fn terminate(&mut self) {
            self.0.borrow_mut().push("kill denied");
        }
        fn finished(&mut self) -> bool {
            self.0.borrow_mut().push("still running");
            false
        }
        fn reap_later(self) {
            self.0.borrow_mut().push("detached reaper");
        }
    }
    #[test]
    fn failed_kill_of_privileged_child_never_blocks_client_cleanup() {
        let events = Rc::new(RefCell::new(vec![]));
        cleanup_child(RootChild(events.clone()));
        assert_eq!(
            *events.borrow(),
            ["kill denied", "still running", "detached reaper"]
        );
    }
}
