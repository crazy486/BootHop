use boothop_core::BootId;
use boothop_platform::linux::arch_identity::{
    IDENTITY_MARKER_PATH, IdentityError, InstalledIdentity,
};

#[test]
fn identity_encodes_exact_fixed_schema_bytes_and_round_trips() {
    let identity = InstalledIdentity::new(BootId(0x1234), [0xab; 32]).unwrap();

    assert_eq!(
        IDENTITY_MARKER_PATH,
        "/var/lib/boothop/arch-direct.identity"
    );
    let bytes = identity.encode();
    assert_eq!(
        bytes,
        b"BOOTHOP_ARCH_V1\nboot_id=1234\noption_sha256=abababababababababababababababababababababababababababababababab\npath=EFI/BootHop/arch.efi\n"
    );
    assert_eq!(InstalledIdentity::parse(&bytes), Ok(identity));
}

#[test]
fn identity_constructor_rejects_existing_grub_boot_id_zero() {
    assert_eq!(
        InstalledIdentity::new(BootId(0), [0; 32]),
        Err(IdentityError::InvalidMarker)
    );
}

#[test]
fn identity_parser_rejects_noncanonical_or_foreign_marker_bytes() {
    let valid = b"BOOTHOP_ARCH_V1\nboot_id=1234\noption_sha256=abababababababababababababababababababababababababababababababab\npath=EFI/BootHop/arch.efi\n";
    let invalid = [
        &b"BOOTHOP_ARCH_V2\nboot_id=1234\noption_sha256=abababababababababababababababababababababababababababababababab\npath=EFI/BootHop/arch.efi\n"[..],
        &b"BOOTHOP_ARCH_V1\nboot_id=123a\noption_sha256=abababababababababababababababababababababababababababababababab\npath=EFI/BootHop/arch.efi\n"[..],
        &b"BOOTHOP_ARCH_V1\nboot_id=0000\noption_sha256=abababababababababababababababababababababababababababababababab\npath=EFI/BootHop/arch.efi\n"[..],
        &b"BOOTHOP_ARCH_V1\nboot_id=1234\noption_sha256=ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB\npath=EFI/BootHop/arch.efi\n"[..],
        &b"BOOTHOP_ARCH_V1\nboot_id=1234\noption_sha256=abab\npath=EFI/BootHop/arch.efi\n"[..],
        &b"BOOTHOP_ARCH_V1\nboot_id=1234\noption_sha256=abababababababababababababababababababababababababababababababab\npath=EFI/Other/arch.efi\n"[..],
        &b"BOOTHOP_ARCH_V1\nboot_id=1234\noption_sha256=abababababababababababababababababababababababababababababababab\npath=EFI/BootHop/arch.efi\nextra=yes\n"[..],
        &b"BOOTHOP_ARCH_V1\nboot_id=1234\noption_sha256=abababababababababababababababababababababababababababababababab\npath=EFI/BootHop/arch.efi"[..],
    ];

    assert!(InstalledIdentity::parse(valid).is_ok());
    for marker in invalid {
        assert!(matches!(
            InstalledIdentity::parse(marker),
            Err(IdentityError::InvalidMarker)
        ));
    }
}
