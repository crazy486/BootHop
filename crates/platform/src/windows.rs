//! Portable Windows firmware policy.
//!
//! This module deliberately contains no Win32 imports.  The native call
//! implementation is added behind `windows::native` in a later task; this
//! boundary stays available to host tests and to Windows builds alike.

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
pub struct WindowsPlatform<'a, F: WindowsCalls, R: RebootCalls> {
    store: &'a mut dyn crate::ProtectedStore,
    firmware: F,
    reboot: R,
}

impl<'a, F: WindowsCalls, R: RebootCalls> WindowsPlatform<'a, F, R> {
    /// Construct an adapter around injected boundaries.  Production native
    /// constructors are private and are wired only by the trusted helper.
    pub fn new(store: &'a mut dyn crate::ProtectedStore, firmware: F, reboot: R) -> Self {
        Self {
            store,
            firmware,
            reboot,
        }
    }
}

impl<F: WindowsCalls, R: RebootCalls> boothop_core::Platform for WindowsPlatform<'_, F, R> {
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
