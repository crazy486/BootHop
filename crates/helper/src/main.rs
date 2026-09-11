#[cfg(target_os = "linux")]
fn main() {
    use boothop_helper::{dispatch, pipe::PipeSession};
    use std::{
        os::fd::AsFd,
        time::{Duration, Instant},
    };
    // Never print panic payloads (which might originate in a trusted adapter).
    std::panic::set_hook(Box::new(|_| {}));
    // SAFETY: geteuid has no preconditions and performs no privileged operation.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        std::process::exit(1);
    }
    let input = std::io::stdin();
    let output = std::io::stdout();
    let Ok(mut io) = PipeSession::new(
        input.as_fd(),
        output.as_fd(),
        Instant::now() + Duration::from_secs(30),
    ) else {
        std::process::exit(1);
    };
    let result = dispatch::serve(euid, &mut io, dispatch::production);
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}
#[cfg(not(target_os = "linux"))]
fn main() {}
