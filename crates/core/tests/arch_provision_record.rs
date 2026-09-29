use boothop_core::{
    ArchProvisionState, BootId, BuildMetadata, CanonicalDevicePathNode, CanonicalIdentity,
    OwnedArchEntry, ProvisioningRecord, ProvisioningStep, PublishMetadata, Residual,
    UninstallingRecord, UninstallingStep, decode_arch_provision_state, encode_arch_provision_state,
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
            owned_entry: ready(),
            step: ProvisioningStep::BootOrderReadBackVerified,
            residual: vec![Residual::BootOrderMayContainEntry],
        }),
        ArchProvisionState::Ready(ready()),
        ArchProvisionState::Uninstalling(UninstallingRecord {
            operation_id: "op-2".into(),
            operation_version: 1,
            owned_entry: ready(),
            step: UninstallingStep::UkiRemoved,
            residual: vec![Residual::BootEntryMayExist],
        }),
    ];
    for state in states {
        let bytes = encode_arch_provision_state(&state).unwrap();
        assert_eq!(decode_arch_provision_state(Some(&bytes)), Ok(state));
    }
}

#[test]
fn state_specific_steps_and_complete_ownership_survive_roundtrip() {
    let entry = ready();
    let provisioning = ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: "before-efi-write".into(),
        operation_version: 1,
        owned_entry: entry.clone(),
        step: ProvisioningStep::BootEntryCreateAttempted,
        residual: vec![
            Residual::BootEntryMayExist,
            Residual::BootOrderMayContainEntry,
        ],
    });
    let uninstalling = ArchProvisionState::Uninstalling(UninstallingRecord {
        operation_id: "remove-owned-entry".into(),
        operation_version: 1,
        owned_entry: entry.clone(),
        step: UninstallingStep::BootOrderRemovalReadBackVerified,
        residual: vec![Residual::UkiMayRemain],
    });

    for state in [provisioning, uninstalling] {
        let bytes = encode_arch_provision_state(&state).unwrap();
        let decoded = decode_arch_provision_state(Some(&bytes)).unwrap();
        assert_eq!(decoded, state);
        match decoded {
            ArchProvisionState::Provisioning(record) => assert_eq!(record.owned_entry, entry),
            ArchProvisionState::Uninstalling(record) => assert_eq!(record.owned_entry, entry),
            _ => unreachable!(),
        }
    }
}

#[test]
fn every_provisioning_and_uninstall_step_roundtrips() {
    let provisioning_steps = [
        ProvisioningStep::UkiPublished,
        ProvisioningStep::BootEntryCreateAttempted,
        ProvisioningStep::BootEntryCreated,
        ProvisioningStep::BootEntryReadBackVerified,
        ProvisioningStep::BootOrderAppendAttempted,
        ProvisioningStep::BootOrderAppended,
        ProvisioningStep::BootOrderReadBackVerified,
    ];
    for step in provisioning_steps {
        let state = ArchProvisionState::Provisioning(ProvisioningRecord {
            operation_id: "op-provision".into(),
            operation_version: 1,
            owned_entry: ready(),
            step,
            residual: vec![Residual::BootOrderMayContainEntry],
        });
        let bytes = encode_arch_provision_state(&state).unwrap();
        assert_eq!(decode_arch_provision_state(Some(&bytes)), Ok(state));
    }

    let uninstall_steps = [
        UninstallingStep::Started,
        UninstallingStep::BootOrderRemovalAttempted,
        UninstallingStep::BootOrderRemoved,
        UninstallingStep::BootOrderRemovalReadBackVerified,
        UninstallingStep::BootEntryRemovalAttempted,
        UninstallingStep::BootEntryRemoved,
        UninstallingStep::BootEntryRemovalReadBackVerified,
        UninstallingStep::UkiRemovalAttempted,
        UninstallingStep::UkiRemoved,
    ];
    for step in uninstall_steps {
        let state = ArchProvisionState::Uninstalling(UninstallingRecord {
            operation_id: "op-uninstall".into(),
            operation_version: 1,
            owned_entry: ready(),
            step,
            residual: vec![Residual::BootEntryMayExist, Residual::UkiMayRemain],
        });
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
        decode_arch_provision_state(Some(br#"{"version":1,"state":{"kind":"Ready"}}"#)),
        Err(boothop_core::Error::UnsupportedRecordVersion { found: 1 })
    );
    assert_eq!(
        decode_arch_provision_state(Some(b"not json")),
        Err(boothop_core::Error::CorruptRecord)
    );
    assert_eq!(
        decode_arch_provision_state(Some(br#"{"version":2,"state":"Ready","entry":{}}"#)),
        Err(boothop_core::Error::CorruptRecord)
    );
    assert_eq!(
        decode_arch_provision_state(Some(br#"{"version":2,"state":{"kind":"FutureState"}}"#,)),
        Err(boothop_core::Error::CorruptRecord)
    );

    let valid =
        encode_arch_provision_state(&ArchProvisionState::Provisioning(ProvisioningRecord {
            operation_id: "op-1".into(),
            operation_version: 1,
            owned_entry: ready(),
            step: ProvisioningStep::BootEntryCreateAttempted,
            residual: vec![],
        }))
        .unwrap();
    let unknown_step = String::from_utf8(valid)
        .unwrap()
        .replace("boot_entry_create_attempted", "future_step");
    assert_eq!(
        decode_arch_provision_state(Some(unknown_step.as_bytes())),
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

#[test]
fn intermediate_states_require_complete_owned_metadata() {
    let mut entry = ready();
    entry.publish.size = 0;
    let provisioning = ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: "op-1".into(),
        operation_version: 1,
        owned_entry: entry.clone(),
        step: ProvisioningStep::BootEntryCreateAttempted,
        residual: vec![],
    });
    let uninstalling = ArchProvisionState::Uninstalling(UninstallingRecord {
        operation_id: "op-2".into(),
        operation_version: 1,
        owned_entry: entry,
        step: UninstallingStep::UkiRemovalAttempted,
        residual: vec![],
    });
    assert_eq!(
        encode_arch_provision_state(&provisioning),
        Err(boothop_core::Error::CorruptRecord)
    );
    assert_eq!(
        encode_arch_provision_state(&uninstalling),
        Err(boothop_core::Error::CorruptRecord)
    );
}
