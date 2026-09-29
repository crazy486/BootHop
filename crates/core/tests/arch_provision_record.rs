use boothop_core::{
    ArchProvisionState, BootId, BuildMetadata, CanonicalDevicePathNode, CanonicalIdentity,
    OwnedArchEntry, ProvisioningRecord, ProvisioningStep, PublishMetadata, Residual,
    UninstallingRecord, decode_arch_provision_state, encode_arch_provision_state,
};

fn identity(path: &str) -> CanonicalIdentity {
    let bytes: Vec<_> = include_str!("../../../fixtures/uefi/synthetic/task1-shape.hex")
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut identity =
        boothop_core::canonicalize(&boothop_core::parse_load_option(&bytes).unwrap()).unwrap();
    let file_length = {
        let CanonicalDevicePathNode::FilePath(file) = &mut identity.nodes[1] else {
            unreachable!()
        };
        file.path_utf16 = path.encode_utf16().collect();
        file.length = ((file.path_utf16.len() + 1) * 2 + 4) as u16;
        file.length
    };
    identity.file_path_list_length = match &identity.nodes[0] {
        CanonicalDevicePathNode::HardDrive(hd) => hd.length + file_length + 4,
        _ => unreachable!(),
    };
    identity
}

fn ready() -> OwnedArchEntry {
    OwnedArchEntry {
        boot_id: BootId(0x1234),
        identity: identity("\\EFI\\BootHop\\arch.efi"),
        identity_version: 1,
        uki_path: "EFI/BootHop/arch.efi".into(),
        build: BuildMetadata {
            kernel: "linux-zen".into(),
            kernel_release: "6.12.1-zen1-1-zen".into(),
            initramfs_sha256: [0x11; 32],
        },
        publish: PublishMetadata {
            sha256: [0x22; 32],
            size: 42,
        },
    }
}

#[test]
fn unprovisioned_is_only_absent_journal() {
    assert_eq!(
        decode_arch_provision_state(None),
        Ok(ArchProvisionState::Unprovisioned)
    );
    assert_eq!(
        decode_arch_provision_state(Some(b"{}")),
        Err(boothop_core::Error::CorruptRecord)
    );
}

#[test]
fn lifecycle_records_roundtrip() {
    let states = [
        ArchProvisionState::Provisioning(ProvisioningRecord {
            operation_id: "op-1".into(),
            operation_version: 1,
            expected_identity: identity("\\EFI\\BootHop\\arch.efi"),
            step: ProvisioningStep::UkiPublished,
            residual: vec![Residual::BootEntryMayExist],
        }),
        ArchProvisionState::Ready(ready()),
        ArchProvisionState::Uninstalling(UninstallingRecord {
            operation_id: "op-2".into(),
            operation_version: 1,
            expected_identity: identity("\\EFI\\BootHop\\arch.efi"),
            step: ProvisioningStep::BootEntryRemoved,
            residual: vec![Residual::UkiMayRemain],
        }),
    ];
    for state in states {
        let bytes = encode_arch_provision_state(&state).unwrap();
        assert_eq!(decode_arch_provision_state(Some(&bytes)), Ok(state));
    }
}

#[test]
fn unknown_or_corrupt_record_fails_closed() {
    assert!(matches!(
        decode_arch_provision_state(Some(br#"{"version":999,"state":"Ready"}"#)),
        Err(boothop_core::Error::UnsupportedRecordVersion { found: 999 })
    ));
    assert_eq!(
        decode_arch_provision_state(Some(b"not json")),
        Err(boothop_core::Error::CorruptRecord)
    );
    assert_eq!(
        decode_arch_provision_state(Some(br#"{"version":1,"state":"Ready","entry":{}}"#)),
        Err(boothop_core::Error::CorruptRecord)
    );
}

#[test]
fn owned_entry_requires_supported_identity_and_fixed_path() {
    let mut entry = ready();
    entry.identity_version = 2;
    assert_eq!(
        encode_arch_provision_state(&ArchProvisionState::Ready(entry)),
        Err(boothop_core::Error::UnsupportedIdentityComponent)
    );

    let mut entry = ready();
    entry.uki_path = "EFI/BootHop/other.efi".into();
    assert_eq!(
        encode_arch_provision_state(&ArchProvisionState::Ready(entry)),
        Err(boothop_core::Error::CorruptRecord)
    );

    let mut entry = ready();
    entry.identity = identity("\\EFI\\BOOT\\BOOTX64.EFI");
    assert_eq!(
        encode_arch_provision_state(&ArchProvisionState::Ready(entry)),
        Err(boothop_core::Error::CorruptRecord)
    );
}
