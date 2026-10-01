//! Dedicated setup arguments. This interface is never dispatched through daily helper IPC.
use boothop_platform::linux::arch_uki::is_safe_flavor;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupArgs {
    pub flavor: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliError {
    NotRoot,
    Usage,
}

pub fn parse_setup_args(args: &[String], euid: u32) -> Result<SetupArgs, CliError> {
    if euid != 0 {
        return Err(CliError::NotRoot);
    }
    if args.len() != 3 || args[0] != "--kernel" || args[2] != "--apply" {
        return Err(CliError::Usage);
    }
    let looks_like_boot_id = args[1].len() == 8
        && args[1].starts_with("Boot")
        && args[1][4..].bytes().all(|byte| byte.is_ascii_hexdigit());
    if !is_safe_flavor(&args[1]) || looks_like_boot_id {
        return Err(CliError::Usage);
    }
    Ok(SetupArgs {
        flavor: args[1].clone(),
    })
}
