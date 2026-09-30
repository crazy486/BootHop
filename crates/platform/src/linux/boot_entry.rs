use super::{
    LinuxCalls,
    firmware::{self, Metadata, OpenKind},
};
use boothop_core::{
    ArchProvisionState, BootId, Error, ProvisioningStep, arch_uki_load_option_from_identity,
    canonicalize, parse_load_option, serialize_load_option,
};
use std::fmt;

const EFIVARFS: u64 = 0xde5e81e4;
const ATTRIBUTES: u32 = 7;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootEntrySpec {
    pub boot_id: BootId,
    /// This is accepted only to compare with the journaled fixed identity; it is never UI input.
    pub identity: boothop_core::CanonicalIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateMutationState {
    NoEntryCreated,
    MayExist,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootEntryFailure {
    pub error: Error,
    pub mutation: CreateMutationState,
}

impl fmt::Display for BootEntryFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (entry state: {:?})", self.error, self.mutation)
    }
}

impl std::error::Error for BootEntryFailure {}

/// Enumerates all strict Boot#### names, including entries absent from BootOrder. References are
/// retained independently so a dangling BootOrder/BootCurrent ID is never allocated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootNamespace {
    pub occupied: [bool; 65536],
    pub referenced: [bool; 65536],
    pub boot_next_set: bool,
}

/// Typed Boot#### boundary for the root-owned provisioning coordinator. The contained calls are
/// injected in tests; no general-purpose firmware writes are exposed to the GUI/BootNext path.
pub struct BootEntryIo<'a, C: LinuxCalls> {
    calls: &'a mut C,
}

impl<'a, C: LinuxCalls> BootEntryIo<'a, C> {
    pub fn new(calls: &'a mut C) -> Self {
        Self { calls }
    }

    pub fn allocate_boot_id(&mut self) -> Result<BootId, Error> {
        allocate_boot_id(self.calls)
    }

    pub fn create_and_verify(
        &mut self,
        esp: &super::esp_identity::EspPartitionIdentity,
        spec: &BootEntrySpec,
        state: &ArchProvisionState,
    ) -> Result<(), BootEntryFailure> {
        create_and_verify_entry(self.calls, esp, spec, state)
    }
}

impl BootNamespace {
    pub fn candidate(&self) -> Result<BootId, Error> {
        if self.boot_next_set {
            return Err(Error::Busy);
        }
        self.occupied
            .iter()
            .zip(self.referenced.iter())
            .position(|(occupied, referenced)| !occupied && !referenced)
            .map(|id| BootId(id as u16))
            .ok_or(Error::ResourceLimit)
    }
    pub fn contains(&self, id: BootId) -> bool {
        self.occupied[id.0 as usize] || self.referenced[id.0 as usize]
    }
}

/// Reads the entire efivarfs namespace and BootOrder/BootCurrent without changing firmware.
pub fn inspect_boot_namespace<C: LinuxCalls>(calls: &mut C) -> Result<BootNamespace, Error> {
    let dir = firmware::directory(calls)?;
    inspect_namespace_at(calls, &dir)
}

fn inspect_namespace_at<C: LinuxCalls>(
    calls: &mut C,
    dir: &C::Handle,
) -> Result<BootNamespace, Error> {
    let names = calls.names(dir)?;
    if names.len() > 65536 {
        return Err(Error::ResourceLimit);
    }
    let mut occupied = [false; 65536];
    let mut total_name_bytes = 0usize;
    for name in names {
        total_name_bytes = total_name_bytes
            .checked_add(name.len())
            .ok_or(Error::ResourceLimit)?;
        if total_name_bytes > 1_048_576 {
            return Err(Error::ResourceLimit);
        }
        if is_boot_like(&name) {
            let id = strict_boot_id(&name).ok_or(Error::UnsupportedFormat)?;
            occupied[id.0 as usize] = true;
        }
    }
    let boot_order =
        firmware::read_variable(calls, dir, "BootOrder", false)?.ok_or(Error::TargetMissing)?;
    let order = firmware::payload(&boot_order, 7)?;
    if !order.len().is_multiple_of(2) {
        return Err(Error::UnsupportedFormat);
    }
    let mut referenced = [false; 65536];
    for pair in order.as_chunks::<2>().0 {
        referenced[u16::from_le_bytes(*pair) as usize] = true;
    }
    let current =
        firmware::read_variable(calls, dir, "BootCurrent", false)?.ok_or(Error::TargetMissing)?;
    let current = firmware::payload(&current, 6)?;
    let current: [u8; 2] = current.try_into().map_err(|_| Error::UnsupportedFormat)?;
    referenced[u16::from_le_bytes(current) as usize] = true;
    let boot_next_set = if let Some(next) = firmware::read_variable(calls, dir, "BootNext", true)? {
        let next = firmware::payload(&next, 7)?;
        let next: [u8; 2] = next.try_into().map_err(|_| Error::UnsupportedFormat)?;
        referenced[u16::from_le_bytes(next) as usize] = true;
        true
    } else {
        false
    };
    Ok(BootNamespace {
        occupied,
        referenced,
        boot_next_set,
    })
}

pub fn allocate_boot_id<C: LinuxCalls>(calls: &mut C) -> Result<BootId, Error> {
    inspect_boot_namespace(calls)?.candidate()
}

/// Creates an exclusively named Boot#### variable and verifies the exact bytes by reopening it.
/// The caller must durably persist `BootEntryCreateAttempted` before this call. Any uncertain
/// result after exclusive open is returned as `MayExist`; it is never cleaned up or retried here.
pub fn create_and_verify_entry<C: LinuxCalls>(
    calls: &mut C,
    esp: &super::esp_identity::EspPartitionIdentity,
    spec: &BootEntrySpec,
    state: &ArchProvisionState,
) -> Result<(), BootEntryFailure> {
    let state_entry = match state {
        ArchProvisionState::Provisioning(record)
            if record.step == ProvisioningStep::BootEntryCreateAttempted
                && record.residual.is_empty() =>
        {
            &record.owned_entry
        }
        _ => return fail(Error::NotConfigured, CreateMutationState::NoEntryCreated),
    };
    if state_entry.boot_id != spec.boot_id
        || state_entry.identity != spec.identity
        || state_entry
            .publish
            .as_ref()
            .is_none_or(|publish| publish.size == 0)
    {
        return fail(Error::IdentityMismatch, CreateMutationState::NoEntryCreated);
    }
    let expected_option =
        arch_uki_load_option_from_identity(&spec.identity).map_err(|error| BootEntryFailure {
            error,
            mutation: CreateMutationState::NoEntryCreated,
        })?;
    let expected_identity = canonicalize(&expected_option).map_err(|error| BootEntryFailure {
        error,
        mutation: CreateMutationState::NoEntryCreated,
    })?;
    if expected_identity != spec.identity || !identity_matches_esp(&spec.identity, esp) {
        return fail(Error::IdentityMismatch, CreateMutationState::NoEntryCreated);
    }
    let payload = serialize_load_option(&expected_option).map_err(|error| BootEntryFailure {
        error,
        mutation: CreateMutationState::NoEntryCreated,
    })?;
    let mut value = Vec::with_capacity(payload.len() + 4);
    value.extend_from_slice(&ATTRIBUTES.to_le_bytes());
    value.extend_from_slice(&payload);

    let dir = firmware::directory(calls).map_err(|error| BootEntryFailure {
        error,
        mutation: CreateMutationState::NoEntryCreated,
    })?;
    let namespace = inspect_namespace_at(calls, &dir).map_err(|error| BootEntryFailure {
        error,
        mutation: CreateMutationState::NoEntryCreated,
    })?;
    if namespace.boot_next_set {
        return fail(Error::Busy, CreateMutationState::NoEntryCreated);
    }
    if namespace.contains(spec.boot_id) {
        return fail(Error::Busy, CreateMutationState::NoEntryCreated);
    }
    // This second complete observation sits directly adjacent to exclusive create. The O_EXCL
    // open is still the final race arbiter and guarantees no existing variable is overwritten.
    let final_check = inspect_namespace_at(calls, &dir).map_err(|error| BootEntryFailure {
        error,
        mutation: CreateMutationState::NoEntryCreated,
    })?;
    if final_check.boot_next_set {
        return fail(Error::Busy, CreateMutationState::NoEntryCreated);
    }
    if final_check.contains(spec.boot_id) {
        return fail(Error::Busy, CreateMutationState::NoEntryCreated);
    }
    let name = format!("Boot{:04X}-{}", spec.boot_id.0, firmware::GUID);
    let mut fd = match calls.open(&dir, &name, OpenKind::CreateEntry) {
        Ok(fd) => fd,
        Err(17) => return fail(Error::Busy, CreateMutationState::NoEntryCreated),
        Err(raw_code) => {
            return fail(
                firmware::io(boothop_core::PlatformOperation::Open, raw_code),
                CreateMutationState::MayExist,
            );
        }
    };
    let metadata = match calls.metadata(&fd) {
        Ok(metadata) => metadata,
        Err(raw_code) => {
            return fail(
                firmware::io(boothop_core::PlatformOperation::Metadata, raw_code),
                CreateMutationState::MayExist,
            );
        }
    };
    if let Err(error) = valid_efivar_file(metadata) {
        return fail(error, CreateMutationState::MayExist);
    }
    if metadata.size != 0 {
        return fail(Error::ReadbackFailed, CreateMutationState::MayExist);
    }
    let count = match calls.write(&mut fd, &value) {
        Ok(count) if count == value.len() => count,
        Ok(_) => return fail(Error::ReadbackFailed, CreateMutationState::MayExist),
        Err(raw_code) => {
            return fail(
                firmware::io(boothop_core::PlatformOperation::Write, raw_code),
                CreateMutationState::MayExist,
            );
        }
    };
    if count != value.len() {
        return fail(Error::ReadbackFailed, CreateMutationState::MayExist);
    }
    drop(fd);
    let readback =
        firmware::read_variable(calls, &dir, &format!("Boot{:04X}", spec.boot_id.0), false)
            .map_err(|error| BootEntryFailure {
                error,
                mutation: CreateMutationState::MayExist,
            })?
            .ok_or(BootEntryFailure {
                error: Error::TargetMissing,
                mutation: CreateMutationState::MayExist,
            })?;
    let actual = firmware::payload(&readback, ATTRIBUTES).map_err(|error| BootEntryFailure {
        error,
        mutation: CreateMutationState::MayExist,
    })?;
    let parsed = parse_load_option(actual).map_err(|error| BootEntryFailure {
        error,
        mutation: CreateMutationState::MayExist,
    })?;
    let actual_identity = canonicalize(&parsed).map_err(|error| BootEntryFailure {
        error,
        mutation: CreateMutationState::MayExist,
    })?;
    if actual != payload || actual_identity != spec.identity {
        return fail(Error::ReadbackFailed, CreateMutationState::MayExist);
    }
    Ok(())
}

fn identity_matches_esp(
    identity: &boothop_core::CanonicalIdentity,
    esp: &super::esp_identity::EspPartitionIdentity,
) -> bool {
    use boothop_core::CanonicalDevicePathNode;
    matches!(identity.nodes.first(), Some(CanonicalDevicePathNode::HardDrive(hd))
        if hd.partition_number == esp.partition_number
            && hd.partition_start_lba == esp.start_lba
            && hd.partition_size_lba == esp.size_lba
            && hd.partition_signature_uefi_bytes == esp.partition_guid_uefi_bytes
            && hd.mbr_type == 2 && hd.signature_type == 2)
}

fn is_boot_like(name: &[u8]) -> bool {
    if !name
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"Boot"))
    {
        return false;
    }
    !["BootCurrent", "BootNext", "BootOrder", "BootOptionSupport"]
        .iter()
        .any(|stem| {
            let standard = format!("{stem}-{}", firmware::GUID);
            name == standard.as_bytes()
        })
}

fn strict_boot_id(name: &[u8]) -> Option<BootId> {
    if name.len() != 45
        || &name[..4] != b"Boot"
        || name[8] != b'-'
        || &name[9..] != firmware::GUID.as_bytes()
    {
        return None;
    }
    let mut id = 0u16;
    for byte in &name[4..8] {
        id = id * 16
            + match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'A'..=b'F' => u16::from(byte - b'A' + 10),
                _ => return None,
            };
    }
    Some(BootId(id))
}

fn fail<T>(error: Error, mutation: CreateMutationState) -> Result<T, BootEntryFailure> {
    Err(BootEntryFailure { error, mutation })
}

fn valid_efivar_file(meta: Metadata) -> Result<(), Error> {
    firmware::validate(meta, false, true)?;
    if meta.filesystem != EFIVARFS {
        return Err(Error::UnsupportedFormat);
    }
    Ok(())
}
