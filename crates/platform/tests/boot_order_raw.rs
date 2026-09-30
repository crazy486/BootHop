#![cfg(target_os = "linux")]

use boothop_core::{BootId, Error};
use boothop_platform::linux::boot_order::decode_boot_order;

fn raw_order(attributes: u32, ids: &[u16]) -> Vec<u8> {
    let mut bytes = attributes.to_le_bytes().to_vec();
    for id in ids {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes
}

#[test]
fn decodes_exact_attributes_and_little_endian_ids() {
    let value = decode_boot_order(&raw_order(7, &[0x1234, 0xabcd])).unwrap();

    assert_eq!(value.attributes, 7);
    assert_eq!(value.ids, [BootId(0x1234), BootId(0xabcd)]);
}

#[test]
fn rejects_missing_or_inexact_attributes() {
    for bytes in [
        Vec::new(),
        vec![7, 0, 0],
        raw_order(6, &[1]),
        raw_order(15, &[1]),
    ] {
        assert_eq!(decode_boot_order(&bytes), Err(Error::UnsupportedFormat));
    }
}

#[test]
fn rejects_odd_payload_length() {
    let mut bytes = 7u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[1, 0, 2]);

    assert_eq!(decode_boot_order(&bytes), Err(Error::UnsupportedFormat));
}

#[test]
fn accepts_the_complete_u16_domain_once() {
    let ids: Vec<_> = (0..=u16::MAX).collect();
    let value = decode_boot_order(&raw_order(7, &ids)).unwrap();

    assert_eq!(value.ids.len(), 65_536);
    assert_eq!(value.ids.first(), Some(&BootId(0)));
    assert_eq!(value.ids.last(), Some(&BootId(u16::MAX)));
}

#[test]
fn rejects_more_than_the_u16_domain() {
    let ids = vec![0; 65_537];

    assert_eq!(
        decode_boot_order(&raw_order(7, &ids)),
        Err(Error::ResourceLimit)
    );
}

#[test]
fn rejects_duplicate_ids() {
    assert_eq!(
        decode_boot_order(&raw_order(7, &[1, 2, 1])),
        Err(Error::UnsupportedFormat)
    );
}
