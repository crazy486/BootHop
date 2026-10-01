use boothop_core::{BootId, Error};

const EFI_GLOBAL_VARIABLE_GUID_SUFFIX: &[u8] = b"-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const BOOT_ORDER_STEM: &[u8] = b"BootOrder";
const BOOT_NEXT_STEM: &[u8] = b"BootNext";
const BOOT_CURRENT_STEM: &[u8] = b"BootCurrent";
const BOOT_OPTION_SUPPORT_STEM: &[u8] = b"BootOptionSupport";
const MAX_BOOT_ORDER_BYTES: usize = (u16::MAX as usize + 1) * 2;

/// Injected EFI variable operations used by explicit setup primitives.
///
/// `enumerate_variables` must return a complete set of raw efivarfs filenames, including
/// malformed names. `read_variable` takes one exact filename and returns its variable data,
/// excluding efivarfs' four-byte attributes prefix. Implementations must make the two create
/// operations single attempts: exclusive Boot#### creation and one BootOrder replacement.
pub trait SetupFirmware {
    fn enumerate_variables(&mut self) -> Result<Vec<Vec<u8>>, Error>;
    fn read_variable(&mut self, exact_name: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn create_boot_entry_exclusive(&mut self, id: BootId, option: &[u8]) -> Result<(), Error>;
    fn replace_boot_order(&mut self, order: &[u8]) -> Result<(), Error>;
}

/// Proof that this setup operation exclusively created and exactly read back a Boot#### entry.
/// Its private fields and exclusive mutable firmware borrow prevent callers from redirecting the
/// proof to another instance or presenting a pre-existing orphan to `append_tail_exact`.
#[must_use = "append only an entry returned by successful create_exact_entry"]
pub struct CreatedEntry<'firmware, F: SetupFirmware> {
    firmware: &'firmware mut F,
    id: BootId,
    option: Vec<u8>,
}

/// Allocate the lowest unused nonzero Boot#### ID from the complete firmware namespace.
pub fn allocate_unused_id(firmware: &mut impl SetupFirmware) -> Result<BootId, Error> {
    let names = firmware.enumerate_variables()?;
    let mut occupied = [false; u16::MAX as usize + 1];
    // Boot0000 is the established GRUB path and is never a BootHop allocation target.
    occupied[0] = true;
    let mut boot_next_listed = false;

    for name in names {
        match classify_boot_name(&name)? {
            BootName::Entry(id) => occupied[usize::from(id.0)] = true,
            BootName::Next => boot_next_listed = true,
            BootName::Other => {}
            BootName::NotBootLike => {}
        }
    }

    let boot_next = firmware.read_variable(&global_variable_name(BOOT_NEXT_STEM))?;
    if boot_next.is_some() {
        return Err(Error::BootNextConflict);
    }
    if boot_next_listed {
        return Err(Error::UnsupportedFormat);
    }

    for raw_id in 1..=u16::MAX {
        if !occupied[usize::from(raw_id)] {
            return Ok(BootId(raw_id));
        }
    }
    Err(Error::ResourceLimit)
}

/// Exclusively create one Boot#### variable, then require its exact payload readback.
pub fn create_exact_entry<'firmware, F: SetupFirmware>(
    firmware: &'firmware mut F,
    id: BootId,
    option: &[u8],
) -> Result<CreatedEntry<'firmware, F>, Error> {
    if id == BootId(0) {
        return Err(Error::UnsupportedFormat);
    }
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(option.len())
        .map_err(|_| Error::ResourceLimit)?;
    expected.extend_from_slice(option);

    firmware.create_boot_entry_exclusive(id, option)?;
    let actual = firmware.read_variable(&boot_variable_name(id))?;
    if actual.as_deref() != Some(expected.as_slice()) {
        return Err(Error::ReadbackFailed);
    }
    Ok(CreatedEntry {
        firmware,
        id,
        option: expected,
    })
}

/// Decode a complete BootOrder payload and reject malformed or duplicate IDs.
pub fn decode_boot_order(bytes: &[u8]) -> Result<Vec<BootId>, Error> {
    if bytes.len() > MAX_BOOT_ORDER_BYTES {
        return Err(Error::ResourceLimit);
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::UnsupportedFormat);
    }

    let mut seen = [false; u16::MAX as usize + 1];
    let mut ids = Vec::new();
    ids.try_reserve_exact(bytes.len() / 2)
        .map_err(|_| Error::ResourceLimit)?;
    for pair in bytes.as_chunks::<2>().0 {
        let id = u16::from_le_bytes(*pair);
        let slot = &mut seen[usize::from(id)];
        if *slot {
            return Err(Error::UnsupportedFormat);
        }
        *slot = true;
        ids.push(BootId(id));
    }
    Ok(ids)
}

/// Re-read the preconditions, append one ID to the current order, and verify the full result.
pub fn append_tail_exact<F: SetupFirmware>(created: CreatedEntry<'_, F>) -> Result<(), Error> {
    let CreatedEntry {
        firmware,
        id,
        option,
    } = created;
    if id == BootId(0) {
        return Err(Error::UnsupportedFormat);
    }
    if firmware
        .read_variable(&global_variable_name(BOOT_NEXT_STEM))?
        .is_some()
    {
        return Err(Error::BootNextConflict);
    }
    if firmware.read_variable(&boot_variable_name(id))?.as_deref() != Some(option.as_slice()) {
        return Err(Error::ReadbackFailed);
    }

    let current_bytes = firmware
        .read_variable(&global_variable_name(BOOT_ORDER_STEM))?
        .ok_or(Error::TargetMissing)?;
    let current = decode_boot_order(&current_bytes)?;
    if current.first() != Some(&BootId(0)) || current.contains(&id) {
        return Err(Error::UnsupportedFormat);
    }

    let new_length = current_bytes
        .len()
        .checked_add(2)
        .ok_or(Error::ResourceLimit)?;
    if new_length > MAX_BOOT_ORDER_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(new_length)
        .map_err(|_| Error::ResourceLimit)?;
    expected.extend_from_slice(&current_bytes);
    expected.extend_from_slice(&id.0.to_le_bytes());

    // A returned error has an unknown write outcome; never retry or roll it back.
    firmware.replace_boot_order(&expected)?;
    let actual = firmware.read_variable(&global_variable_name(BOOT_ORDER_STEM))?;
    if actual.as_deref() != Some(expected.as_slice()) {
        return Err(Error::ReadbackFailed);
    }
    Ok(())
}

enum BootName {
    Entry(BootId),
    Next,
    Other,
    NotBootLike,
}

fn classify_boot_name(name: &[u8]) -> Result<BootName, Error> {
    if !name
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"Boot"))
    {
        return Ok(BootName::NotBootLike);
    }
    let stem_end = name
        .len()
        .checked_sub(EFI_GLOBAL_VARIABLE_GUID_SUFFIX.len())
        .ok_or(Error::UnsupportedFormat)?;
    if name.get(stem_end..) != Some(EFI_GLOBAL_VARIABLE_GUID_SUFFIX) {
        return Err(Error::UnsupportedFormat);
    }
    let stem = name.get(..stem_end).ok_or(Error::UnsupportedFormat)?;
    match stem {
        BOOT_NEXT_STEM => Ok(BootName::Next),
        BOOT_ORDER_STEM | BOOT_CURRENT_STEM | BOOT_OPTION_SUPPORT_STEM => Ok(BootName::Other),
        _ => parse_boot_id_stem(stem).map(BootName::Entry),
    }
}

fn parse_boot_id_stem(stem: &[u8]) -> Result<BootId, Error> {
    if stem.len() != 8 || !stem.starts_with(b"Boot") {
        return Err(Error::UnsupportedFormat);
    }
    let mut id = 0_u16;
    for byte in stem.get(4..).ok_or(Error::UnsupportedFormat)? {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(Error::UnsupportedFormat),
        };
        id = id
            .checked_mul(16)
            .and_then(|value| value.checked_add(u16::from(nibble)))
            .ok_or(Error::UnsupportedFormat)?;
    }
    Ok(BootId(id))
}

fn global_variable_name(stem: &[u8]) -> Vec<u8> {
    let mut name = Vec::with_capacity(stem.len() + EFI_GLOBAL_VARIABLE_GUID_SUFFIX.len());
    name.extend_from_slice(stem);
    name.extend_from_slice(EFI_GLOBAL_VARIABLE_GUID_SUFFIX);
    name
}

fn boot_variable_name(id: BootId) -> Vec<u8> {
    let mut name = Vec::with_capacity(8 + EFI_GLOBAL_VARIABLE_GUID_SUFFIX.len());
    name.extend_from_slice(format!("Boot{:04X}", id.0).as_bytes());
    name.extend_from_slice(EFI_GLOBAL_VARIABLE_GUID_SUFFIX);
    name
}
