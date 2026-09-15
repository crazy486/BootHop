//! Portable Windows firmware policy.
//!
//! Policy and composition boundary for Windows.  Win32 implementations remain
//! in private target-gated child modules; this public surface is available to
//! host tests and to the Windows production helper wiring.

pub mod firmware;
pub mod privilege;
pub mod reboot;
pub mod store;

pub use firmware::{
    BOOT_ATTRIBUTES, BOOT_CURRENT_ATTRIBUTES, CallError, FirmwareType, GLOBAL_VARIABLE_GUID,
    INITIAL_BUFFER_BYTES, MAX_ENUMERATION_BYTES, MAX_PAYLOAD_BYTES, ReadOutcome, ReadStatus,
    VariableName, WindowsCalls, check_environment, read_next, read_options,
    validate_native_buffer_size,
};

pub use reboot::{RebootCalls, RebootReply, with_shutdown_privilege};

/// The Windows production adapter composes the trusted record store with the
/// closed firmware and reboot seams.  All mutation ordering remains owned by
/// `boothop_core::execute`; this type only maps each semantic operation to the
/// appropriate mechanism.
pub struct WindowsPlatform<S: crate::ProtectedStore, F: WindowsCalls, R: RebootCalls> {
    store: S,
    firmware: F,
    reboot: R,
}

impl<S: crate::ProtectedStore, F: WindowsCalls, R: RebootCalls> WindowsPlatform<S, F, R> {
    /// Construct an adapter around injected boundaries.  Production native
    /// constructors are private and are wired only by the trusted helper.
    pub fn new(store: S, firmware: F, reboot: R) -> Self {
        Self {
            store,
            firmware,
            reboot,
        }
    }
}

impl<S: crate::ProtectedStore, F: WindowsCalls, R: RebootCalls> boothop_core::Platform
    for WindowsPlatform<S, F, R>
{
    fn load_record(&mut self) -> Result<boothop_core::RecordState, boothop_core::Error> {
        self.store.load()
    }

    fn save_record(
        &mut self,
        target: &boothop_core::TargetRecord,
    ) -> Result<(), boothop_core::Error> {
        self.store.save(target)
    }

    fn read_options(&mut self) -> Result<boothop_core::OptionInventory, boothop_core::Error> {
        firmware::read_options(&mut self.firmware)
    }

    fn read_next(&mut self) -> Result<Option<boothop_core::BootId>, boothop_core::Error> {
        firmware::read_next(&mut self.firmware)
    }

    fn write_next(&mut self, target: boothop_core::BootId) -> Result<(), boothop_core::Error> {
        firmware::set_boot_next(&mut self.firmware, target)
    }

    fn rollback_next(
        &mut self,
        _original: Option<boothop_core::BootId>,
        _written: boothop_core::BootId,
    ) -> boothop_core::RollbackOutcome {
        // Windows has no firmware compare-and-swap and BootHop cannot prove
        // exclusivity against other writers.  Never issue a speculative
        // restore in the default production adapter.
        boothop_core::RollbackOutcome::Unsafe
    }

    fn reboot(&mut self) -> boothop_core::RebootOutcome {
        self.reboot.request_reboot().into_core()
    }

    fn check_environment(&mut self) -> Result<(), boothop_core::Error> {
        firmware::check_environment(&mut self.firmware)
    }
}

pub use reboot::classify_reboot_result;

/// Opaque owner of the native Windows production adapter.  The concrete
/// protected store, firmware calls, reboot calls, and operation capability
/// cannot be named or constructed by dependent crates.
#[cfg(windows)]
pub struct ProductionPlatform {
    inner: WindowsPlatform<
        store::WindowsProtectedStore<store::native::SystemWindowsStoreCalls>,
        firmware::native::SystemWindowsCalls,
        reboot::native::SystemRebootCalls,
    >,
}

/// Construct the native platform after the trusted helper has acquired its
/// operation guard. This opens and validates the protected ProgramData store;
/// it does not access firmware, enable privileges, request shutdown, or
/// reboot.
///
/// # Safety
///
/// The caller must already hold `Global\\BootHop.Operation.v1` exclusively and
/// retain that guard for the entire lifetime of the returned platform. The
/// helper must not release the guard until the terminal response has been
/// transmitted. This boundary is unsafe because the capability proving that
/// invariant is owned by the separate helper crate.
#[cfg(windows)]
pub unsafe fn production_after_operation_guard() -> Result<ProductionPlatform, boothop_core::Error>
{
    let store = store::WindowsProtectedStore::open(
        store::native::SystemWindowsStoreCalls::new(),
        store::OperationCapability::new(),
    )?;
    Ok(ProductionPlatform {
        inner: WindowsPlatform::new(
            store,
            firmware::native::SystemWindowsCalls::new(),
            reboot::native::SystemRebootCalls::new(),
        ),
    })
}

#[cfg(windows)]
impl boothop_core::Platform for ProductionPlatform {
    fn load_record(&mut self) -> Result<boothop_core::RecordState, boothop_core::Error> {
        self.inner.load_record()
    }
    fn save_record(
        &mut self,
        target: &boothop_core::TargetRecord,
    ) -> Result<(), boothop_core::Error> {
        self.inner.save_record(target)
    }
    fn read_options(&mut self) -> Result<boothop_core::OptionInventory, boothop_core::Error> {
        self.inner.read_options()
    }
    fn read_next(&mut self) -> Result<Option<boothop_core::BootId>, boothop_core::Error> {
        self.inner.read_next()
    }
    fn write_next(&mut self, target: boothop_core::BootId) -> Result<(), boothop_core::Error> {
        self.inner.write_next(target)
    }
    fn rollback_next(
        &mut self,
        original: Option<boothop_core::BootId>,
        written: boothop_core::BootId,
    ) -> boothop_core::RollbackOutcome {
        self.inner.rollback_next(original, written)
    }
    fn reboot(&mut self) -> boothop_core::RebootOutcome {
        self.inner.reboot()
    }
    fn check_environment(&mut self) -> Result<(), boothop_core::Error> {
        self.inner.check_environment()
    }
}
