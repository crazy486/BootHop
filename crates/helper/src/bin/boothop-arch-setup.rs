#[cfg(target_os = "linux")]
fn main() {
    use boothop_helper::arch_setup_cli::parse_setup_args;
    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|s| s.into_string())
        .collect()
    {
        Ok(args) => args,
        Err(_) => {
            eprintln!("usage: boothop-arch-setup --kernel FLAVOR --apply");
            std::process::exit(64);
        }
    };
    // SAFETY: geteuid has no preconditions and performs no privileged operation.
    let euid = unsafe { libc::geteuid() };
    if parse_setup_args(&args, euid).is_err() {
        eprintln!("usage: root must run boothop-arch-setup --kernel FLAVOR --apply");
        std::process::exit(64);
    }
    // The host adapter is deliberately absent until package route, preset, hook, ESP,
    // and efivarfs operations can be checked together on a disposable Arch machine.
    eprintln!("Arch direct setup is unavailable: production adapter has not been verified");
    std::process::exit(1);
}

#[cfg(not(target_os = "linux"))]
fn main() {}
