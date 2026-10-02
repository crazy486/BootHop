#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use std::process::ExitCode;

    use boothop_helper::{
        arch_setup_cli::parse_setup_args, m4_guest_guard::require_current_qemu_uefi_guest,
    };
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
            eprintln!("usage: boothop-m4-guest-setup --kernel FLAVOR --apply");
            return ExitCode::from(64);
        }
    };
    // SAFETY: geteuid has no preconditions and performs no privileged operation.
    let euid = unsafe { libc::geteuid() };
    let args = match parse_setup_args(&args, euid) {
        Ok(args) => args,
        Err(_) => {
            eprintln!("usage: root must run boothop-m4-guest-setup --kernel FLAVOR --apply");
            return ExitCode::from(64);
        }
    };

    if let Err(error) = require_current_qemu_uefi_guest() {
        eprintln!("refusing Arch setup outside the marked QEMU UEFI guest: {error:?}");
        return ExitCode::FAILURE;
    }

    let calls = match NativeArchCalls::open() {
        Ok(calls) => calls,
        Err(error) => {
            eprintln!("could not open the Arch setup backend: {error}");
            return ExitCode::FAILURE;
        }
    };
    let backend = SystemArchSetupBackend::new(calls);
    let result = run_with_backend(backend, |backend| {
        run_arch_setup(SetupIntent::new(args.flavor), backend)
    });
    match result {
        Ok(identity) => {
            println!(
                "Arch setup completed; created Boot{:04X}",
                identity.boot_id().0
            );
            ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!("Arch setup failed: {failure:?}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run_with_backend<B, R>(mut backend: B, run: impl FnOnce(&mut B) -> R) -> R {
    run(&mut backend)
}

#[cfg(not(target_os = "linux"))]
fn main() {}
