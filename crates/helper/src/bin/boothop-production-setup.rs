#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use std::process::ExitCode;

    use boothop_helper::arch_setup_cli::dispatch_setup;
    use boothop_platform::linux::{
        arch_setup::{SetupIntent, run_arch_setup},
        arch_setup_native::NativeArchCalls,
        arch_setup_system::SystemArchSetupBackend,
    };

    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect()
    {
        Ok(args) => args,
        Err(_) => {
            eprintln!("usage: boothop-production-setup --kernel FLAVOR --apply");
            return ExitCode::from(64);
        }
    };
    // SAFETY: geteuid has no preconditions and performs no privileged operation.
    let euid = unsafe { libc::geteuid() };
    let result = dispatch_setup(&args, euid, |setup| {
        let calls = NativeArchCalls::open()
            .map_err(|error| format!("could not open the Arch setup backend: {error}"))?;
        let mut backend = SystemArchSetupBackend::new(calls);
        run_arch_setup(SetupIntent::new(setup.flavor), &mut backend)
            .map_err(|failure| format!("Arch setup failed: {failure:?}"))
    });

    match result {
        Ok(Ok(identity)) => {
            println!(
                "Arch setup completed; created Boot{:04X}",
                identity.boot_id().0
            );
            ExitCode::SUCCESS
        }
        Ok(Err(error)) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("usage: root must run boothop-production-setup --kernel FLAVOR --apply");
            ExitCode::from(64)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
