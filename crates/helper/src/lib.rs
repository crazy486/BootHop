pub mod dispatch;
#[cfg(target_os = "linux")]
pub mod lock;
#[cfg(target_os = "linux")]
pub mod pipe;
/// Compatibility re-export. Production protocol ownership lives in the
/// dependency-free (apart from core/serde) protocol crate; helper remains the
/// only crate that adds privileged platform dispatch.
pub use boothop_protocol as protocol;
