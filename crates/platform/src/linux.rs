pub mod firmware;
pub mod reboot;
pub mod store;

use crate::ProtectedStore;
use boothop_core::{
    BootId, Error, OptionInventory, Platform, RebootOutcome, RecordState, TargetRecord,
};
use firmware::{Metadata, OpenKind};
use reboot::{Probe, Reply};

/// Trusted syscall boundary; implementations own descriptor lifetimes. Never supplied by IPC.
/// Opens are CLOEXEC and NOFOLLOW; Directory also requires DIRECTORY, ReadVariable is
/// read-only, and CreateNext is WRONLY|CREATE|EXCL with fresh offset zero, never TRUNC/APPEND.
/// Metadata includes fstat, filesystem type and mount flags. Names must be bounded and
/// enumeration errors preserved; no implementation may repair mounts or firmware variables.
pub trait LinuxCalls {
    type Handle;
    fn root(&mut self) -> Result<Self::Handle, i32>;
    fn open(&mut self, dir: &Self::Handle, name: &str, kind: OpenKind)
    -> Result<Self::Handle, i32>;
    fn metadata(&mut self, fd: &Self::Handle) -> Result<Metadata, i32>;
    fn names(&mut self, dir: &Self::Handle) -> Result<Vec<Vec<u8>>, Error>;
    fn read(&mut self, fd: &mut Self::Handle, buffer: &mut [u8]) -> Result<usize, i32>;
    fn write(&mut self, fd: &mut Self::Handle, buffer: &[u8]) -> Result<usize, i32>;
    fn probe(&mut self) -> Result<Probe, Error>;
    fn reboot_with_flags(&mut self, flags: u64) -> Reply;
}

pub struct LinuxPlatform<'a, C: LinuxCalls> {
    store: &'a mut dyn ProtectedStore,
    calls: C,
    reboot_ready: bool,
}
impl<'a, C: LinuxCalls> LinuxPlatform<'a, C> {
    pub fn new(store: &'a mut dyn ProtectedStore, calls: C) -> Self {
        Self {
            store,
            calls,
            reboot_ready: false,
        }
    }
}
impl<C: LinuxCalls> Platform for LinuxPlatform<'_, C> {
    fn load_record(&mut self) -> Result<RecordState, Error> {
        self.store.load()
    }
    fn save_record(&mut self, target: &TargetRecord) -> Result<(), Error> {
        self.store.save(target)
    }
    fn read_options(&mut self) -> Result<OptionInventory, Error> {
        firmware::read_options(&mut self.calls)
    }
    fn read_next(&mut self) -> Result<Option<BootId>, Error> {
        firmware::read_next(&mut self.calls)
    }
    fn write_next(&mut self, target: BootId) -> Result<(), Error> {
        firmware::write_next(&mut self.calls, target)
    }
    fn check_environment(&mut self) -> Result<(), Error> {
        self.reboot_ready = false;
        firmware::directory(&mut self.calls)?;
        reboot::validate_probe(&self.calls.probe()?)?;
        self.reboot_ready = true;
        Ok(())
    }
    fn reboot(&mut self) -> RebootOutcome {
        if !self.reboot_ready {
            return RebootOutcome::Rejected;
        }
        self.reboot_ready = false;
        match self.calls.reboot_with_flags(1) {
            Reply::Success => RebootOutcome::Accepted,
            Reply::ExplicitDenial | Reply::NotSent => RebootOutcome::Rejected,
            Reply::DisconnectedAfterSend | Reply::TimedOutAfterSend => RebootOutcome::Unknown,
        }
    }
}
/// Fixed system resources, initialized only by explicit production use. Tests inject LinuxCalls.
pub struct SystemLinuxCalls {
    connection: Option<zbus::blocking::Connection>,
}
impl<'a> LinuxPlatform<'a, SystemLinuxCalls> {
    /// The caller supplies an already locked protected store and holds it through reporting.
    /// Does not repair/mount firmware or open a bus at construction.
    pub fn system(store: &'a mut dyn ProtectedStore) -> Self {
        Self::new(store, SystemLinuxCalls { connection: None })
    }
}
impl LinuxCalls for SystemLinuxCalls {
    type Handle = std::os::fd::OwnedFd;
    fn root(&mut self) -> Result<Self::Handle, i32> {
        rustix::fs::open(
            "/",
            firmware::open_flags(OpenKind::Directory),
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| e.raw_os_error())
    }
    fn open(
        &mut self,
        dir: &Self::Handle,
        name: &str,
        kind: OpenKind,
    ) -> Result<Self::Handle, i32> {
        firmware::native_open(dir, name, kind)
    }
    fn metadata(&mut self, fd: &Self::Handle) -> Result<Metadata, i32> {
        firmware::native_metadata(fd)
    }
    fn names(&mut self, dir: &Self::Handle) -> Result<Vec<Vec<u8>>, Error> {
        firmware::native_names(dir)
    }
    fn read(&mut self, fd: &mut Self::Handle, buffer: &mut [u8]) -> Result<usize, i32> {
        rustix::io::read(fd, buffer).map_err(|e| e.raw_os_error())
    }
    fn write(&mut self, fd: &mut Self::Handle, buffer: &[u8]) -> Result<usize, i32> {
        rustix::io::write(fd, buffer).map_err(|e| e.raw_os_error())
    }
    fn probe(&mut self) -> Result<Probe, Error> {
        reboot::native_probe(&mut self.connection)
    }
    fn reboot_with_flags(&mut self, flags: u64) -> Reply {
        reboot::native_reboot(&self.connection, flags)
    }
}
