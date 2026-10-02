#[cfg(target_os = "linux")]
pub mod arch_setup_cli;
pub mod dispatch;
#[cfg(target_os = "linux")]
pub mod lock;
#[cfg(all(target_os = "linux", feature = "m4-guest-setup"))]
pub mod m4_guest_guard;
#[cfg(target_os = "linux")]
pub mod pipe;
pub mod windows;
/// Compatibility re-export. Production protocol ownership lives in the
/// dependency-free (apart from core/serde) protocol crate; helper remains the
/// only crate that adds privileged platform dispatch.
pub use boothop_protocol as protocol;
