use std::collections::HashMap;

use boothop_core::{BootId, Error};
use boothop_platform::linux::setup_firmware::{
    SetupFirmware, allocate_unused_id, append_tail_exact, create_exact_entry, decode_boot_order,
};

const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const BOOT_NEXT: &[u8] = b"BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const BOOT_ORDER: &[u8] = b"BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c";

fn variable_name(stem: &str) -> Vec<u8> {
    format!("{stem}-{GUID}").into_bytes()
}

fn boot_name(id: BootId) -> Vec<u8> {
    variable_name(&format!("Boot{:04X}", id.0))
}

fn encode_order(ids: &[u16]) -> Vec<u8> {
    ids.iter().flat_map(|id| id.to_le_bytes()).collect()
}

#[derive(Default)]
struct FakeFirmware {
    names: Vec<Vec<u8>>,
    variables: HashMap<Vec<u8>, Vec<u8>>,
    create_calls: usize,
    replace_calls: usize,
    reads: Vec<Vec<u8>>,
    create_error: Option<Error>,
    created_value_override: Option<Vec<u8>>,
    replace_error: Option<Error>,
    order_after_replace: Option<Vec<u8>>,
}

impl FakeFirmware {
    fn with_order(ids: &[u16]) -> Self {
        let mut firmware = Self::default();
        firmware
            .variables
            .insert(BOOT_ORDER.to_vec(), encode_order(ids));
        firmware
    }
}

impl SetupFirmware for FakeFirmware {
    fn enumerate_variables(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.names.clone())
    }

    fn read_variable(&mut self, name: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.reads.push(name.to_vec());
        Ok(self.variables.get(name).cloned())
    }

    fn create_boot_entry_exclusive(&mut self, id: BootId, option: &[u8]) -> Result<(), Error> {
        self.create_calls += 1;
        if let Some(error) = &self.create_error {
            return Err(error.clone());
        }
        if self.variables.contains_key(&boot_name(id)) {
            return Err(Error::Busy);
        }
        self.variables.insert(
            boot_name(id),
            self.created_value_override
                .clone()
                .unwrap_or_else(|| option.to_vec()),
        );
        Ok(())
    }

    fn replace_boot_order(&mut self, order: &[u8]) -> Result<(), Error> {
        self.replace_calls += 1;
        if let Some(error) = &self.replace_error {
            return Err(error.clone());
        }
        self.variables.insert(
            BOOT_ORDER.to_vec(),
            self.order_after_replace
                .clone()
                .unwrap_or_else(|| order.to_vec()),
        );
        Ok(())
    }
}

#[test]
fn allocator_skips_orphan_boot_entries_outside_boot_order() {
    let mut firmware = FakeFirmware::with_order(&[0]);
    firmware.names = vec![variable_name("Boot0000"), variable_name("Boot0001")];

    assert_eq!(allocate_unused_id(&mut firmware), Ok(BootId(2)));
}

#[test]
fn allocator_refuses_malformed_boot_like_variable_names() {
    for malformed in [
        b"Boot000g-8be4df61-93ca-11d2-aa0d-00e098032b8c".as_slice(),
        b"Boot00001-8be4df61-93ca-11d2-aa0d-00e098032b8c".as_slice(),
        b"Boot00af-8be4df61-93ca-11d2-aa0d-00e098032b8c".as_slice(),
        b"Boot0007-deadbeef-93ca-11d2-aa0d-00e098032b8c".as_slice(),
        b"boot0007-8be4df61-93ca-11d2-aa0d-00e098032b8c".as_slice(),
    ] {
        let mut firmware = FakeFirmware::with_order(&[0]);
        firmware.names = vec![variable_name("Boot0000"), malformed.to_vec()];

        assert_eq!(
            allocate_unused_id(&mut firmware),
            Err(Error::UnsupportedFormat),
            "malformed name {:?} must fail closed",
            String::from_utf8_lossy(malformed),
        );
    }
}

#[test]
fn allocator_refuses_when_boot_next_is_present() {
    let mut firmware = FakeFirmware::with_order(&[0]);
    firmware.names = vec![variable_name("Boot0000"), BOOT_NEXT.to_vec()];
    firmware.variables.insert(BOOT_NEXT.to_vec(), vec![0xff]);

    assert_eq!(
        allocate_unused_id(&mut firmware),
        Err(Error::BootNextConflict)
    );
    assert_eq!(firmware.create_calls, 0);
    assert_eq!(firmware.replace_calls, 0);
}

#[test]
fn allocator_reports_exhaustion_after_all_boot_ids_are_occupied() {
    let mut firmware = FakeFirmware::default();
    firmware.names = (0..=u16::MAX)
        .map(|id| variable_name(&format!("Boot{id:04X}")))
        .collect();

    assert_eq!(allocate_unused_id(&mut firmware), Err(Error::ResourceLimit));
}

#[test]
fn create_entry_uses_one_exclusive_attempt_and_stops_on_collision() {
    let mut firmware = FakeFirmware {
        create_error: Some(Error::Busy),
        ..FakeFirmware::default()
    };

    assert!(matches!(
        create_exact_entry(&mut firmware, BootId(7), b"serialized option"),
        Err(Error::Busy),
    ));
    assert_eq!(firmware.create_calls, 1);
    assert!(firmware.reads.is_empty());
}

#[test]
fn create_entry_requires_an_exact_variable_readback() {
    let mut firmware = FakeFirmware {
        created_value_override: Some(b"different option".to_vec()),
        ..FakeFirmware::default()
    };

    assert!(matches!(
        create_exact_entry(&mut firmware, BootId(7), b"serialized option"),
        Err(Error::ReadbackFailed),
    ));
    assert_eq!(firmware.create_calls, 1);
    assert_eq!(firmware.reads, [boot_name(BootId(7))]);
}

#[test]
fn boot_order_decoder_rejects_odd_length_and_duplicate_ids() {
    assert_eq!(decode_boot_order(&[0x00]), Err(Error::UnsupportedFormat));
    assert_eq!(
        decode_boot_order(&[0x00, 0x00, 0x00, 0x00]),
        Err(Error::UnsupportedFormat),
    );
}

#[test]
fn append_preserves_the_complete_order_and_reads_it_back_exactly() {
    let mut firmware = FakeFirmware::with_order(&[0, 7, 2]);
    let created = create_exact_entry(&mut firmware, BootId(8), b"new option").unwrap();
    let expected = [0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00];

    assert_eq!(append_tail_exact(created), Ok(()));
    assert_eq!(
        firmware.variables.get::<[u8]>(BOOT_ORDER).unwrap(),
        &expected
    );
    assert_eq!(firmware.replace_calls, 1);
    assert_eq!(
        firmware
            .reads
            .iter()
            .filter(|name| name.as_slice() == BOOT_ORDER)
            .count(),
        2,
        "read the fresh full order and its full exact readback",
    );
}

#[test]
fn matching_preexisting_orphan_cannot_be_appended() {
    let mut firmware = FakeFirmware::with_order(&[0, 7]);
    firmware.names = vec![variable_name("Boot0000"), variable_name("Boot0008")];
    firmware
        .variables
        .insert(boot_name(BootId(8)), b"matching option".to_vec());

    assert!(matches!(
        create_exact_entry(&mut firmware, BootId(8), b"matching option"),
        Err(Error::Busy),
    ));
    // The exclusive-create collision returns no CreatedEntry proof, which is the only input
    // accepted by append_tail_exact.
    assert_eq!(firmware.create_calls, 1);
    assert_eq!(firmware.replace_calls, 0);
    assert_eq!(
        firmware.variables.get::<[u8]>(BOOT_ORDER).unwrap(),
        &encode_order(&[0, 7])
    );
}

#[test]
fn creation_proof_remains_bound_to_its_firmware_instance() {
    let mut creator = FakeFirmware::with_order(&[0, 7]);
    let created = create_exact_entry(&mut creator, BootId(8), b"matching option").unwrap();
    let mut other = FakeFirmware::with_order(&[0, 7]);
    other.names = vec![variable_name("Boot0000"), variable_name("Boot0008")];
    other
        .variables
        .insert(boot_name(BootId(8)), b"matching option".to_vec());

    assert_eq!(append_tail_exact(created), Ok(()));
    assert_eq!(
        creator.variables.get::<[u8]>(BOOT_ORDER).unwrap(),
        &encode_order(&[0, 7, 8]),
    );
    assert_eq!(other.replace_calls, 0);
    assert_eq!(
        other.variables.get::<[u8]>(BOOT_ORDER).unwrap(),
        &encode_order(&[0, 7])
    );
}

#[test]
fn append_requires_boot_zero_first_and_does_not_write_on_invalid_order() {
    let mut firmware = FakeFirmware::with_order(&[7, 0]);
    let created = create_exact_entry(&mut firmware, BootId(8), b"new option").unwrap();

    assert!(append_tail_exact(created).is_err());
    assert_eq!(firmware.replace_calls, 0);
}

#[test]
fn append_detects_an_order_changed_before_full_readback_without_retrying() {
    let mut firmware = FakeFirmware::with_order(&[0, 7]);
    firmware.order_after_replace = Some(encode_order(&[0, 7, 8, 9]));
    let created = create_exact_entry(&mut firmware, BootId(8), b"new option").unwrap();

    assert_eq!(append_tail_exact(created), Err(Error::ReadbackFailed),);
    assert_eq!(firmware.replace_calls, 1);
}

#[test]
fn append_does_not_retry_an_uncertain_order_write() {
    let mut firmware = FakeFirmware::with_order(&[0, 7]);
    firmware.replace_error = Some(Error::FirmwareWriteFailed { raw_code: 5 });
    let created = create_exact_entry(&mut firmware, BootId(8), b"new option").unwrap();

    assert_eq!(
        append_tail_exact(created),
        Err(Error::FirmwareWriteFailed { raw_code: 5 }),
    );
    assert_eq!(firmware.replace_calls, 1);
    assert_eq!(
        firmware
            .reads
            .iter()
            .filter(|name| name.as_slice() == BOOT_ORDER)
            .count(),
        1,
        "an uncertain write stops before any retry",
    );
}
