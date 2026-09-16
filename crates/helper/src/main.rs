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
#[cfg(windows)]
fn main() {
    let argv = std::env::args_os().skip(1).collect::<Vec<_>>();
    let Ok(args) = boothop_helper::windows::pipe::parse_args_os(&argv) else {
        std::process::exit(1);
    };
    // Keep native endpoint failures generic at the process boundary; the
    // authenticated transport carries the only structured terminal result.
    let status = boothop_helper::windows::pipe::run(args)
        .map(|_| 0)
        .unwrap_or(1);
    std::process::exit(status);
}

#[cfg(not(any(target_os = "linux", windows)))]
fn main() {}
